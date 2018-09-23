import socket, ssl, select

# rs_proxyType
RS_PT_NONE = 0
RS_PT_SOCKS4 = 1
RS_PT_SOCKS5 = 2
RS_PT_HTTP = 3

# rs_errorType
RS_ET_OWN = 0 # rocksock-specific error
RS_ET_SYS = 1 # system error with errno
RS_ET_GAI = 2 # dns resolution subsystem error
RS_ET_SSL = 3 # ssl subsystem error

# rs_error
RS_E_NO_ERROR = 0
RS_E_NULL = 1
RS_E_EXCEED_PROXY_LIMIT = 2
RS_E_NO_SSL = 3
RS_E_NO_SOCKET = 4
RS_E_HIT_TIMEOUT = 5
RS_E_OUT_OF_BUFFER = 6
RS_E_SSL_GENERIC = 7
RS_E_SOCKS4_NOAUTH = 8
RS_E_SOCKS5_AUTH_EXCEEDSIZE = 9
RS_E_SOCKS4_NO_IP6 = 10
RS_E_PROXY_UNEXPECTED_RESPONSE = 11
RS_E_TARGETPROXY_CONNECT_FAILED = 12
RS_E_PROXY_AUTH_FAILED = 13
RS_E_HIT_READTIMEOUT = 14
RS_E_HIT_WRITETIMEOUT = 15
RS_E_HIT_CONNECTTIMEOUT = 16
RS_E_PROXY_GENERAL_FAILURE = 17
RS_E_TARGETPROXY_NET_UNREACHABLE = 18
RS_E_TARGETPROXY_HOST_UNREACHABLE = 19
RS_E_TARGETPROXY_CONN_REFUSED = 20
RS_E_TARGETPROXY_TTL_EXPIRED = 21
RS_E_PROXY_COMMAND_NOT_SUPPORTED = 22
RS_E_PROXY_ADDRESSTYPE_NOT_SUPPORTED = 23
RS_E_REMOTE_DISCONNECTED = 24
RS_E_NO_PROXYSTORAGE = 25
RS_E_HOSTNAME_TOO_LONG = 26
RS_E_INVALID_PROXY_URL = 27


class RocksockException(Exception):
	def __init__(self, error, failedproxy=None, errortype=RS_ET_OWN, *args, **kwargs):
		Exception.__init__(self,*args,**kwargs)
		self.error = error
		self.errortype = errortype
		self.failedproxy = failedproxy

	def get_failedproxy(self):
		return self.failedproxy

	def get_error(self):
		return self.error

	def reraise(self):
		import sys
		ei = sys.exc_info()
		raise ei[0], ei[1], ei[2]
#		import traceback, sys
#		traceback.print_exc(file=sys.stderr)
#		raise self

	def get_errormessage(self):
		errordict = {
			RS_E_NO_ERROR : "no error",
			RS_E_NULL: "NULL pointer passed",
			RS_E_EXCEED_PROXY_LIMIT: "exceeding maximum number of proxies",
			RS_E_NO_SSL: "can not establish SSL connection, since library was not compiled with USE_SSL define",
			RS_E_NO_SOCKET:	"socket is not set up, maybe you should call connect first",
			RS_E_HIT_TIMEOUT: "timeout reached on operation",
			RS_E_OUT_OF_BUFFER: "supplied buffer is too small",
			RS_E_SSL_GENERIC: "generic SSL error", # the C version uses this error when the SSL library does not report any specific error, otherwise errortype SSL will be set and the SSL errorcode be used
			RS_E_SOCKS4_NOAUTH:"SOCKS4 authentication not implemented",
			RS_E_SOCKS5_AUTH_EXCEEDSIZE: "maximum length for SOCKS5 servername/password/username is 255",
			RS_E_SOCKS4_NO_IP6: "SOCKS4 is not compatible with IPv6",
			RS_E_PROXY_UNEXPECTED_RESPONSE: "the proxy sent an unexpected response",
			RS_E_TARGETPROXY_CONNECT_FAILED: "could not connect to target proxy",
			RS_E_PROXY_AUTH_FAILED:	"proxy authentication failed or authd not enabled",
			RS_E_HIT_READTIMEOUT : "timeout reached on read operation",
			RS_E_HIT_WRITETIMEOUT :	"timeout reached on write operation",
			RS_E_HIT_CONNECTTIMEOUT : "timeout reached on connect operation",
			RS_E_PROXY_GENERAL_FAILURE : "proxy general failure",
			RS_E_TARGETPROXY_NET_UNREACHABLE : "proxy-target: net unreachable",
			RS_E_TARGETPROXY_HOST_UNREACHABLE : "proxy-target: host unreachable",
			RS_E_TARGETPROXY_CONN_REFUSED : "proxy-target: connection refused",
			RS_E_TARGETPROXY_TTL_EXPIRED : "proxy-target: TTL expired",
			RS_E_PROXY_COMMAND_NOT_SUPPORTED : "proxy: command not supported",
			RS_E_PROXY_ADDRESSTYPE_NOT_SUPPORTED : "proxy: addresstype not supported",
			RS_E_REMOTE_DISCONNECTED : "remote socket closed connection",
			RS_E_NO_PROXYSTORAGE : "no proxy storage assigned",
			RS_E_HOSTNAME_TOO_LONG : "hostname exceeds 255 chars",
			RS_E_INVALID_PROXY_URL : "invalid proxy URL string"
		}
		if self.errortype == RS_ET_SYS:
			import errno
			if self.error in errno.errorcode:
				msg = "ERRNO: " + errno.errorcode[self.error]
			else:
				msg = "ERRNO: invalid errno: " + str(self.error)
		elif self.errortype == RS_ET_GAI:
			msg = "GAI: " + self.failedproxy
		elif self.errortype == RS_ET_SSL:
			msg = errordict[self.error]
			if self.error == RS_E_SSL_GENERIC and self.failedproxy != None:
				msg += ': ' + self.failedproxy #failedproxy is repurposed for SSL exceptions
		else: #RS_ET_OWN
			msg = errordict[self.error]
		return msg


class RocksockHostinfo():
	def __init__(self, host, port):
		self.host = host
		self.port = port

class RocksockProxy():
	def __init__(self, host, port, type, username = None, password=None, **kwargs):
		typemap = { 'none'   : RS_PT_NONE,
			    'socks4' : RS_PT_SOCKS4,
			    'socks5' : RS_PT_SOCKS5,
			    'http'   : RS_PT_HTTP }
		self.type = typemap[type] if type in typemap else type
		self.username = username
		self.password = password
		self.hostinfo = RocksockHostinfo(host, port)

def RocksockProxyFromURL(url):
	# valid URL: socks5://[user:pass@]hostname:port
	x = url.find('://')
	if x == -1: return None
	t = url[:x]
	url = url[x+len('://'):]
	x = url.rfind(':')
	if x == -1: return None # port is obligatory
	port = int(url[x+len(':'):]) #TODO: catch exception when port is non-numeric
	url = url[:x]
	x = url.find('@')
	if x != -1:
		u, p = url[:x].split(':')
		url = url[x+len('@'):]
	else:
		u, p = (None, None)
	return RocksockProxy(host=url, port=port, type=t, username=u, password=p)


class Rocksock():
	def __init__(self, host=None, port=0, verifycert=False, timeout=0, proxies=None, **kwargs):
		if 'ssl' in kwargs and kwargs['ssl'] == True:
			self.sslcontext = ssl.create_default_context()
			self.sslcontext.check_hostname = False
			if not verifycert: self.sslcontext.verify_mode = ssl.CERT_NONE
		else:
			self.sslcontext = None
		self.proxychain = proxies if proxies else []
		target = RocksockProxy(host, port, RS_PT_NONE)
		self.proxychain.append(target)
		self.sock = None
		self.timeout = timeout

	def connect(self):

		af, sa = self._resolve(self.proxychain[0].hostinfo, True)
		try:
			x = af+1
		except TypeError:
			raise RocksockException(-3, "unexpected problem resolving DNS, try again", errortype=RS_ET_GAI)
#			print "GOT A WEIRD AF"
#			print af
#			raise RocksockException(-6666, af, errortype=RS_ET_GAI)

		self.sock = socket.socket(af, socket.SOCK_STREAM)
		self.sock.settimeout(None if self.timeout == 0 else self.timeout)
		try:
			self.sock.connect((sa[0], sa[1]))
		except socket.timeout:
			raise RocksockException(RS_E_HIT_TIMEOUT)
		except socket.error as e:
			raise RocksockException(e.errno, errortype=RS_ET_SYS)

		for pnum in xrange(1, len(self.proxychain)):
			curr = self.proxychain[pnum]
			prev = self.proxychain[pnum-1]
			self._connect_step(pnum)

		if self.sslcontext:
			try:
				self.sock = self.sslcontext.wrap_socket(self.sock, server_hostname=self.proxychain[len(self.proxychain)-1].hostinfo.host)
			except ssl.SSLError as e:
				reason = self._get_ssl_exception_reason(e)
				#if hasattr(e, 'library'): subsystem = e.library
				raise RocksockException(RS_E_SSL_GENERIC, reason, errortype=RS_ET_SSL)
			except socket.error as e:
				raise RocksockException(e.errno, errortype=RS_ET_SYS)
			except Exception as e:
				raise e
			"""
			while True:
				try:
					self.sock.do_handshake()
					break
				except ssl.SSLWantReadError:
					select.select([self.sock], [], [])
				except ssl.SSLWantWriteError:
					select.select([], [self.sock], [])
			"""


	def disconnect(self):
		if self.sock is None: return
		try:
			self.sock.shutdown(socket.SHUT_RDWR)
		except socket.error:
			pass
		self.sock.close()
		self.sock = None

	def canread(self):
		return select.select([self.sock], [], [], 0)[0]

	def send(self, buf):
		if self.sock is None:
			raise RocksockException(RS_E_NO_SOCKET)
		return self.sock.sendall(buf)

	def _get_ssl_exception_reason(self, e):
		s = ''
		if hasattr(e, 'reason'): s = e.reason
		elif hasattr(e, 'message'): s = e.message
		elif hasattr(e, 'args'): s = e.args[0]
		return s

	def recv(self, count=-1):
		data = ''
		while count:
			try:
				n = count if count != -1 else 4096
				if n >= 1024*1024: n = 1024*1024
				chunk = self.sock.recv(n)
			except socket.timeout:
				raise RocksockException(RS_E_HIT_TIMEOUT)
			except ssl.SSLError as e:
				s = self._get_ssl_exception_reason(e)
				if s == 'The read operation timed out':
					raise RocksockException(RS_E_HIT_READTIMEOUT)
				else:
					raise RocksockException(RS_E_SSL_GENERIC, s, errortype=RS_ET_SSL)
			if len(chunk) == 0:
				raise RocksockException(RS_E_REMOTE_DISCONNECTED)
			data += chunk
			if count == -1: break
			else: count -= len(chunk)
		return data

	def recvline(self):
		s = ''
		c = '\0'
		while c != '\n':
			c = self.recv(1)
			if c == '': return s
			s += c
		return s

	def recvuntil(self, until):
		s = self.recv(len(until))
		endc = until[-1:]
		while not (s[-1:] == endc and s.endswith(until)):
			s += self.recv(1)
		return s

	def _isnumericipv4(self, ip):
		try:
			a,b,c,d = ip.split('.')
			if int(a) < 256 and int(b) < 256 and int(c) < 256 and int(d) < 256:
				return True
			return False
		except:
			return False

	def _resolve(self, hostinfo, want_v4=True):
		if self._isnumericipv4(hostinfo.host):
			return socket.AF_INET, (hostinfo.host, hostinfo.port)
		try:
			for res in socket.getaddrinfo(hostinfo.host, hostinfo.port, \
					socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
				af, socktype, proto, canonname, sa = res
				if want_v4 and af != socket.AF_INET: continue
				if af != socket.AF_INET and af != socket.AF_INET6: continue
				else: return af, sa

		except socket.gaierror as e:
			eno, str = e.args
			raise RocksockException(eno, str, errortype=RS_ET_GAI)

		return None, None

	def _ip_to_int(self, ip):
		a,b,c,d = ip.split('.')
		h = "0x%.2X%.2X%.2X%.2X"%(int(a),int(b),int(c),int(d))
		return int(h, 16)

	def _ip_to_bytes(self, ip):
		ip = self._ip_to_int(ip)
		a = (ip & 0xff000000) >> 24
		b = (ip & 0x00ff0000) >> 16
		c = (ip & 0x0000ff00) >> 8
		d = (ip & 0x000000ff) >> 0
		return chr(a) + chr(b) + chr(c) + chr(d)

	def _setup_socks4_header(self, v4a, dest):
		buf = '\x04\x01'
		buf += chr(dest.hostinfo.port / 256)
		buf += chr(dest.hostinfo.port % 256)
		if v4a:
			buf += '\0\0\0\x01'
		else:
			af, sa = self._resolve(dest, True)
			if af != socket.AF_INET: raise RocksockException(RS_E_SOCKS4_NO_IP6)
			buf += self._ip_to_bytes(sa[0])
		buf += '\0'
		if v4a: buf += dest.hostinfo.host + '\0'
		return buf

	def _connect_socks4(self, header, pnum):
		self.send(header)
		res = self.recv(8)
		if len(res) < 8 or ord(res[0]) != 0:
			raise RocksockException(RS_E_PROXY_UNEXPECTED_RESPONSE, pnum-1)
		ch = ord(res[1])
		if ch == 0x5a:
			pass
		elif ch == 0x5b:
			raise RocksockException(RS_E_TARGETPROXY_CONNECT_FAILED, pnum-1)
		elif ch == 0x5c or ch == 0x5d:
			return RocksockException(RS_E_PROXY_AUTH_FAILED, pnum-1)
		else:
			raise RocksockException(RS_E_PROXY_UNEXPECTED_RESPONSE, pnum-1)

	def _setup_socks5_header(self, proxy):
		buf = '\x05'
		if proxy.username and proxy.password:
			buf += '\x02\x00\x02'
		else:
			buf += '\x01\x00'
		return buf

	def _connect_socks5(self, header, pnum):
		self.send(header)
		res = self.recv(2)
		if len(res) != 2 or res[0] != '\x05':
			raise RocksockException(RS_E_PROXY_UNEXPECTED_RESPONSE, pnum-1)
		if res[1] == '\xff':
			raise RocksockException(RS_E_PROXY_AUTH_FAILED, pnum-1)

		if ord(res[1]) == 2:
			px = self.proxychain[pnum-1]
			if px.username and px.password:
				pkt = '\x01%c%s%c%s'%(len(px.username),px.username,len(px.password),px.password)
				self.send(pkt)
				res = self.recv(2)
				if len(res) < 2 or res[1] != '\0':
					raise RocksockException(RS_E_PROXY_AUTH_FAILED, pnum-1)
			else: raise RocksockException(RS_E_PROXY_AUTH_FAILED, pnum-1)
		dst = self.proxychain[pnum]
		numeric = self._isnumericipv4(dst.hostinfo.host)
		if numeric:
			dstaddr = self._ip_to_bytes(dst.hostinfo.host)
		else:
			dstaddr = chr(len(dst.hostinfo.host)) + dst.hostinfo.host

		pkt = '\x05\x01\x00%c%s%c%c'% (1 if numeric else 3, dstaddr, dst.hostinfo.port / 256, dst.hostinfo.port % 256)
		self.send(pkt)
		res = self.recv()
		if len(res) < 2 or res[0] != '\x05':
			raise RocksockException(RS_E_PROXY_UNEXPECTED_RESPONSE, pnum-1)
		ch = ord(res[1])
		if ch == 0: pass
		elif ch == 1: raise RocksockException(RS_E_PROXY_GENERAL_FAILURE, pnum-1)
		elif ch == 2: raise RocksockException(RS_E_PROXY_AUTH_FAILED, pnum-1)
		elif ch == 3: raise RocksockException(RS_E_TARGETPROXY_NET_UNREACHABLE, pnum-1)
		elif ch == 4: raise RocksockException(RS_E_TARGETPROXY_HOST_UNREACHABLE, pnum-1)
		elif ch == 5: raise RocksockException(RS_E_TARGETPROXY_CONN_REFUSED, pnum-1)
		elif ch == 6: raise RocksockException(RS_E_TARGETPROXY_TTL_EXPIRED, pnum-1)
		elif ch == 7: raise RocksockException(RS_E_PROXY_COMMAND_NOT_SUPPORTED, pnum-1)
		elif ch == 8: raise RocksockException(RS_E_PROXY_ADDRESSTYPE_NOT_SUPPORTED, pnum-1)
		else: raise RocksockException(RS_E_PROXY_UNEXPECTED_RESPONSE, pnum-1)


	def _connect_step(self, pnum):
		prev = self.proxychain[pnum -1]
		curr = self.proxychain[pnum]
		if prev.type == RS_PT_SOCKS4:
			s4a = self._setup_socks4_header(True, curr)
			try:
				self._connect_socks4(s4a, pnum)
			except RocksockException as e:
				if e.get_error() == RS_E_TARGETPROXY_CONNECT_FAILED:
					s4 = self._setup_socks4_header(self, False, curr)
					self._connect_socks4(s4a, pnum)
				else: raise e
		elif prev.type == RS_PT_SOCKS5:
			s5 = self._setup_socks5_header(prev)
			self._connect_socks5(s5, pnum)
		elif prev.type == RS_PT_HTTP:
			dest = self.proxychain[pnum]
			self.send("CONNECT %s:%d HTTP/1.1\r\n\r\n"%(dest.hostinfo.host, dest.hostinfo.port))
			resp = self.recv()
			if len(resp) <12:
				raise RocksockException(RS_E_PROXY_UNEXPECTED_RESPONSE, pnum-1)
			if resp[9] != '2':
				raise RocksockException(RS_E_TARGETPROXY_CONNECT_FAILED, pnum-1)


if __name__ == '__main__':
	proxies = [
#		RocksockProxyFromURL("socks5://foo:bar@localhost:1080"),
#		RocksockProxyFromURL("socks5://10.0.0.3:1080"),
		RocksockProxyFromURL("socks5://127.0.0.1:31339"),
	]
	proxies = None
	#rs = Rocksock(host='googleff242342423f.com', port=443, ssl=True, proxies=proxies)
	rs = Rocksock(host='google.com', port=80, ssl=False, proxies=proxies)
	try:
		rs.connect()
	except RocksockException as e:
		print e.get_errormessage()
		e.reraise()
	rs.send('GET / HTTP/1.0\r\n\r\n')
	print rs.recvline()
	rs.disconnect()
	rs.connect()
	rs.send('GET / HTTP/1.0\r\n\r\n')
	print rs.recvline()

