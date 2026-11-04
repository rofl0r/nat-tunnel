from __future__ import print_function
import socket, select, os, threading, hashlib, rocksock, time, sys, codecs, re, hmac

PY3 = sys.version_info[0] == 3
if PY3:
	def _b(a, b):
		return bytes(a, b)
else:
	def _b(a, b):
		return bytes(a)

NONCE_LEN = 8

def _get_nonce():
	return codecs.encode(os.urandom(NONCE_LEN), 'hex')

def _hash(str):
	return _b(hashlib.sha256(str).hexdigest(), 'utf-8')

# CONN address format: IPv4 is "1.2.3.4:1234", IPv6 is "[::1]:1234".
# The brackets are required: a bare IPv6 address contains colons,
# so split(b':') cannot tell address from port. Use a pre-compiled
# regex and strip the brackets on parse; _format_addr adds them.
_CONN_RE = re.compile(br'CONN:\[(?P<ip>[^\]]+)\]:(?P<port>\d+)\b|CONN:(?P<ip4>\d{1,3}(?:\.\d{1,3}){3}):(?P<port4>\d+)\b')
def _parse_conn(line):
	# Return (ip_str, port_int) or None. Line is bytes without newline.
	m = _CONN_RE.search(line)
	if not m:
		return None
	if m.group('ip') is not None:
		return m.group('ip').decode('utf-8', 'replace'), int(m.group('port'))
	return m.group('ip4').decode('utf-8', 'replace'), int(m.group('port4'))

def _format_addr(addr):
	ip, port = addr[0], addr[1]
	if ':' in ip:  # IPv6: wrap in brackets
		ip = '[' + ip + ']'
	ip = _b(ip, 'utf-8')
	return b"%s:%d"%(ip, port)

def _timestamp():
	return _b(time.strftime('[%Y-%m-%d %H:%M:%S] ', time.localtime(time.time())), 'utf-8')

class Tunnel():
	def __init__(self, fds, fdc, caddr):
		self.fds = fds
		self.fdc = fdc
		self.done = threading.Event()
		self.t = None
	def _cleanup(self):
		if self.fdc: self.fdc.close()
		if self.fds: self.fds.close()
		self.fdc = None
		self.fds = None
	def _threadfunc(self):
		# Half-close bug: any EOF (or recv error) broke the loop and
		# closed both sockets at once, discarding data still in
		# flight in the other direction. Now EOF on one side only
		# shutdown()s that side's write half; the other direction
		# keeps draining until it also reaches EOF, then close.
		open_dirs = {self.fds, self.fdc}
		while open_dirs:
			try:
				a,b,c = select.select(list(open_dirs), [], [])
			except (ValueError, OSError):
				break
			if not a:
				continue
			other = {self.fds: self.fdc, self.fdc: self.fds}[a[0]]
			try:
				buf = a[0].recv(1024)
			except (ConnectionResetError, OSError):
				buf = b''
			if len(buf) == 0:
				open_dirs.discard(a[0])
				try:
					other.shutdown(socket.SHUT_WR)
				except OSError:
					pass
				continue
			try:
				# send() may write only part of buf; old code dropped
				# the rest silently. sendall() writes all of it.
				other.sendall(buf)
			except (BrokenPipeError, ConnectionResetError, OSError):
				break
		self._cleanup()
		self.done.set()
	def start(self):
		self.t = threading.Thread(target=self._threadfunc)
		self.t.daemon = True
		self.t.start()
	def finished(self):
		return self.done.is_set()
	def reap(self):
		self.t.join()

class NATClient():
	def __init__(self, secret, upstream_ip, upstream_port, localserv_ip, localserv_port):
		self.secret = secret
		self.localserv_ip = localserv_ip
		self.localserv_port = localserv_port
		self.upstream_ip = upstream_ip
		self.upstream_port = upstream_port
		self.controlsock = None
		self.next_csock = None
		self.threads = []

	def _setup_sock(self, cmd):
		sock = rocksock.Rocksock(host=self.upstream_ip, port=self.upstream_port)
		sock.connect()
		nonce = sock.recv(NONCE_LEN*2 + 1).rstrip(b'\n')
		# Rocksock has send(), not sendall(); its send() already
		# calls the underlying socket sendall().
		sock.send(_hash(cmd + self.secret + nonce) + b'\n')
		return sock

	def _reconnect(self):
		# Lost-control fix: old doit() let recvline() raise on
		# EOF and the whole client exited, killing all tunnels.
		# Tear down control+spare and retry handshake with backoff.
		for attr in ('controlsock', 'next_csock'):
			old = getattr(self, attr)
			if old is not None:
				try:
					old.disconnect()
				except Exception:
					pass
			setattr(self, attr, None)
		while True:
			try:
				self.controlsock = self._setup_sock(b'adm')
				self.next_csock = self._setup_sock(b'skt')
				return
			except Exception as e:
				print(_timestamp() + b'reconnect failed: %s (retry in 2s)' % str(e).encode())
				time.sleep(2)

	def setup(self):
		self.controlsock = self._setup_sock(b'adm')
		self.next_csock =  self._setup_sock(b'skt')

	def doit(self):
		while True:
			i = 0
			while i < len(self.threads):
				if self.threads[i].finished():
					self.threads[i].reap()
					self.threads.pop(i)
				else:
					i += 1

			l = self.controlsock.recvline()
			if not l or not l.endswith(b'\n'):
				# EOF or truncated line: control socket is gone,
				# do not crash; re-establish control+spare.
				print(_timestamp() + b'lost control socket, reconnecting')
				self._reconnect()
				continue
			print(_timestamp() + l.rstrip(b'\n'))
			if l.startswith(b'CONN:'):
				parsed=_parse_conn(l.rstrip(b'\n'))
				if parsed is None:
					print(_timestamp() + b'unparsable CONN line: %r' % l)
					continue
				addr=parsed
				# Local connect failure bug: old code let connect()
				# raise, killing the client and stranding the
				# public client that the server had paired with
				# our spare socket. Now log it, drop the already
				# paired spare socket (tell the server there is no
				# spare by force-closing it; the server notices on
				# its select), and arm a fresh spare.
				try:
					local_conn = rocksock.Rocksock(host=self.localserv_ip, port=self.localserv_port)
					local_conn.connect()
				except Exception as e:
					print(_timestamp() + b'local connect failed: %s' % str(e).encode())
					if self.next_csock is not None:
						try:
							self.next_csock.disconnect()
						except Exception:
							pass
						self.next_csock = None
					try:
						self.next_csock = self._setup_sock(b'skt')
					except Exception:
						print(_timestamp() + b'lost spare socket, reconnecting')
						self._reconnect()
					continue
				thread = Tunnel(local_conn.sock, self.next_csock.sock, addr)
				thread.start()
				self.threads.append(thread)
				# The spare socket setup can fail if the server died
				# right after sending CONN; that is a lost control
				# socket, not a reason to crash. Reconnect instead.
				try:
					self.next_csock = self._setup_sock(b'skt')
				except Exception:
					print(_timestamp() + b'lost spare socket, reconnecting')
					self._reconnect()


class NATSrv():
	def _isnumericipv4(self, ip):
		# Old check only tested int(field) < 256, so it accepted
		# negatives, spaces and unicode digits. ipaddress is strict:
		# dotted decimal, 0-255 per octet, no leading junk.
		import ipaddress as _ipaddr
		try:
			_ipaddr.IPv4Address(ip)
			return True
		except ValueError:
			return False

	def _resolve(self, host, port, want_v4=False, passive=False):
		# AI_PASSIVE was passed even for outbound client connects
		# and want_v4 defaulted True, so IPv6-only hosts could
		# never resolve. passive is now only for listen sockets,
		# and both address families are accepted by default.
		if self._isnumericipv4(host):
			return socket.AF_INET, (host, port)
		flags = socket.AI_PASSIVE if passive else 0
		for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, flags):
			af, socktype, proto, canonname, sa = res
			if want_v4 and af != socket.AF_INET: continue
			if af != socket.AF_INET and af != socket.AF_INET6: continue
			else: return af, sa
		return None, None

	def __init__(self, secret, upstream_listen_ip, upstream_port, client_listen_ip, client_port):
		self.up_port = upstream_port
		self.up_ip = upstream_listen_ip
		self.client_port = client_port
		self.client_ip = client_listen_ip
		self.secret = secret
		self.threads = []
		self.su = None
		self.sc = None
		self.control_socket = None
		self.next_upstream_socket = None
		self.hashlen = len(_hash(b''))

	def _setup_listen_socket(self, listenip, port):
		af, sa = self._resolve(listenip, port, passive=True)
		if af is None:
			raise ValueError('cannot resolve %r' % listenip)
		s = socket.socket(af, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			s.bind(sa)  # sa is 2-tuple for v4, 4-tuple for v6
		except TypeError:
			s.bind((sa[0], sa[1]))
		s.listen(1)
		return s

	def setup(self):
		self.su = self._setup_listen_socket(self.up_ip, self.up_port)
		self.sc = self._setup_listen_socket(self.client_ip, self.client_port)

	def wait_conn_up(self):
		conn, addr = self.su.accept()
		# Handshake blocking bug: the old code blocked in recv()
		# below with no timeout, so a client that connected and
		# sent nothing froze the whole server (no admin, spare,
		# or public accepts). Pre-auth sockets now get a short
		# timeout that is cleared once auth succeeds.
		conn.settimeout(10)
		nonce = _get_nonce()
		print(_timestamp() + b"CONN: %s (nonce: %s) ... "%(_format_addr(addr), nonce), end='')
		conn.sendall(nonce + b'\n')
		# TCP may split the hash across packets; a single recv()
		# could return a short read and wrongly reject a good
		# client. Read exactly hashlen+1 bytes instead.
		cmd = b''
		try:
			while len(cmd) < 1 + self.hashlen:
				chunk = conn.recv(1 + self.hashlen - len(cmd))
				if not chunk:
					break
				cmd += chunk
		except (socket.timeout, TimeoutError, OSError):
			cmd = b''
		cmd = cmd.rstrip(b'\n')
		if hmac.compare_digest(cmd, _hash(b'adm' + self.secret + nonce)):
			conn.settimeout(None)
			if self.control_socket:
				self.control_socket.close()
			# Orphan spare bug: a new admin replaced the control
			# socket but left the old spare tunnel socket in
			# place, so the next public client was paired with a
			# tunnel from the dead admin session. Close it.
			if self.next_upstream_socket:
				try:
					self.next_upstream_socket.close()
				except OSError:
					pass
				self.next_upstream_socket = None
			self.control_socket = conn
			print("OK (admin)")
		elif hmac.compare_digest(cmd, _hash(b'skt' + self.secret + nonce)):
			conn.settimeout(None)
			print("OK (tunnel)")
			if not self.control_socket:
				conn.close()
			else:
				self.next_upstream_socket = conn
		else:
			print("rejected!")
			conn.close()

	def wait_conn_client(self):
		conn, addr = self.sc.accept()
		self.control_socket.sendall(b"CONN:%s\n"%_format_addr(addr))
		thread = Tunnel(self.next_upstream_socket, conn, addr)
		thread.start()
		self.threads.append(thread)
		self.next_upstream_socket = None

	def doit(self):
		while True:
			i = 0
			while i < len(self.threads):
				if self.threads[i].finished():
					self.threads[i].reap()
					self.threads.pop(i)
				else:
					i += 1
			if not self.control_socket:
				self.wait_conn_up()
			if not self.next_upstream_socket:
				self.wait_conn_up()
			if self.control_socket and self.next_upstream_socket:
				# Bug: select list omitted next_upstream_socket, so the
				# 'lost spare' branch below could never fire and a dead
				# spare was paired with the next public client.
				a,b,c = select.select([self.sc, self.control_socket, self.next_upstream_socket], [], [])
				if self.control_socket in a:
					print("lost control socket")
					self.control_socket.close()
					self.control_socket = None
					continue
				if self.next_upstream_socket in a:
					print("lost spare upstream socket")
					self.next_upstream_socket.close()
					self.next_upstream_socket = None
					continue
				if self.sc in a:
					self.wait_conn_client()


if __name__ == "__main__":
	import argparse
	desc=(
		"NAT Tunnel v0.01\n"
		"----------------\n"
		"If you have access to a server with public IP and unfiltered ports\n"
		"you can run NAT Tunnel (NT)  server on the server, and NT client\n"
		"on your box behind NAT.\n"
		"the server requires 2 open ports: one for communication with the\n"
		"NT client (--admin), the other for regular clients to connect to\n"
		"(--public: this is the port you want your users to use).\n"
		"\n"
		"The NT client opens a connection to the server's admin ip/port.\n"
		"As soon as the server receives a new connection, it signals the\n"
		"NT client, which then creates a new tunnel connection to the\n"
		"server, which is then connected to the desired service on the\n"
		"NT client's side (--local)\n"
		"\n"
		"The connection between NT Client and NT Server on the admin\n"
		"interface is protected by a shared secret against unauthorized use.\n"
		"An adversary who can intercept packets could crack the secret\n"
		"if it's of insufficient complexity. At least 10 random\n"
		"characters and numbers are recommended.\n"
		"\n"
		"Example:\n"
		"You have a HTTP server listening on your local machine on port 80.\n"
		"You want to make it available on your cloud server/VPS/etc's public\n"
		"IP on port 7000.\n"
		"We use port 8000 on the cloud server for the control channel.\n"
		"\n"
		"Server:\n"
		"    %s --mode server --secret s3cretP4ss --public 0.0.0.0:7000 --admin 0.0.0.0:8000\n"
		"Client:\n"
		"    %s --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:8000\n"
	) % (sys.argv[0], sys.argv[0])
	if len(sys.argv) < 2 or (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
		print(desc)
	parser = argparse.ArgumentParser(description='')
	parser.add_argument('--secret', help='shared secret between natserver/client', type=str, default='', required=True)
	parser.add_argument('--mode', help='work mode: server or client', type=str, default='server', required=True)
	parser.add_argument('--public', help='(server only) ip:port where we will listen for regular clients', type=str, default='0.0.0.0:8080', required=False)
	parser.add_argument('--local', help='(client only) ip:port of the local target service', type=str, default="localhost:80", required=False)
	parser.add_argument('--admin', help='ip:port tuple for admin/upstream/control connection', type=str, default="0.0.0.0:8081", required=False)
	args = parser.parse_args()
	adminip, adminport = args.admin.split(':')
	if args.mode == 'server':
		clientip, clientport = args.public.split(':')
		srv = NATSrv(_b(args.secret, 'utf-8'), adminip, int(adminport), clientip, int(clientport))
		srv.setup()
		srv.doit()
	else:
		localip, localport = args.local.split(':')
		cl = NATClient(_b(args.secret, 'utf-8'), adminip, int(adminport), localip, int(localport))
		cl.setup()
		cl.doit()
