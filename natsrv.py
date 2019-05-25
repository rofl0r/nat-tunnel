import socket, select, os, threading, hashlib, rocksock, time, sys

NONCE_LEN = 8

def _get_nonce():
	return os.urandom(NONCE_LEN).encode('hex')

def _hash(str):
	return hashlib.sha256(str).hexdigest()

def _format_addr(addr):
	ip, port = addr
	return "%s:%d"%(ip, port)

def _timestamp():
	return time.strftime('[%Y-%m-%d %H:%M:%S] ', time.localtime(time.time()))

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
		while True:
			a,b,c = select.select([self.fds, self.fdc], [], [])
			try:
				buf = a[0].recv(1024)
			except:
				buf = ''
			if len(buf) == 0:
				break
			try:
				if a[0] == self.fds:
					self.fdc.send(buf)
				else:
					self.fds.send(buf)
			except:
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
		nonce = sock.recv(NONCE_LEN*2 + 1).rstrip('\n')
		sock.send(_hash(cmd + self.secret + nonce) + '\n')
		return sock

	def setup(self):
		self.controlsock = self._setup_sock('adm')
		self.next_csock =  self._setup_sock('skt')

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
			print(_timestamp() + l.rstrip('\n'))
			if l.startswith('CONN:'):
				addr=l.rstrip('\n').split(':')[1]
				local_conn = rocksock.Rocksock(host=self.localserv_ip, port=self.localserv_port)
				local_conn.connect()
				thread = Tunnel(local_conn.sock, self.next_csock.sock, addr)
				thread.start()
				self.threads.append(thread)
				self.next_csock = self._setup_sock('skt')


class NATSrv():
	def _isnumericipv4(self, ip):
		try:
			a,b,c,d = ip.split('.')
			if int(a) < 256 and int(b) < 256 and int(c) < 256 and int(d) < 256:
				return True
			return False
		except:
			return False

	def _resolve(self, host, port, want_v4=True):
		if self._isnumericipv4(host):
			return socket.AF_INET, (host, port)
		for res in socket.getaddrinfo(host, port, \
				socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
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
		self.hashlen = len(_hash(""))

	def _setup_listen_socket(self, listenip, port):
		af, sa = self._resolve(listenip, port)
		s = socket.socket(af, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((sa[0], sa[1]))
		s.listen(1)
		return s

	def setup(self):
		self.su = self._setup_listen_socket(self.up_ip, self.up_port)
		self.sc = self._setup_listen_socket(self.client_ip, self.client_port)

	def wait_conn_up(self):
		conn, addr = self.su.accept()
		nonce = _get_nonce()
		sys.stdout.write(_timestamp() + "CONN: %s (nonce: %s) ... "%(_format_addr(addr), nonce))
		conn.send(nonce + '\n')
		cmd = conn.recv(1 + self.hashlen).rstrip('\n')
		if cmd == _hash('adm' + self.secret + nonce):
			if self.control_socket:
				self.control_socket.close()
			self.control_socket = conn
			print("OK (admin)")
		elif cmd == _hash('skt' + self.secret + nonce):
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
		self.control_socket.send("CONN:%s\n"%_format_addr(addr))
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
				a,b,c = select.select([self.sc, self.control_socket, ], [], [])
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
		srv = NATSrv(args.secret, adminip, int(adminport), clientip, int(clientport))
		srv.setup()
		srv.doit()
	else:
		localip, localport = args.local.split(':')
		cl = NATClient(args.secret, adminip, int(adminport), localip, int(localport))
		cl.setup()
		cl.doit()
