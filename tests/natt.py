#!/usr/bin/env python3
"""Test framework for natsrv (NAT Tunnel).

One entry point per test. Run all tests with "make test" or
"python3 tests/natt.py", or name tests on the command line:

    python3 tests/natt.py tunnel_basic spare_rst
    python3 tests/natt.py --list
    NATT_SLOW=1 python3 tests/natt.py      # include slow tests

Fault injection: every client connection to the server admin
port can be routed through FaultProxy. The proxy can drop a
connection with RST, drop it with FIN, or freeze it, i.e. stop
forwarding bytes while both sockets stay open. That covers the
three ways a TCP path dies: reset, orderly close, and blackhole.

Each test gets its own ports, its own server and client
processes, its own backend service and its own log files. Nothing
is shared, so tests can run in any order and one failure never
leaks into the next test.
"""

import errno
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATSRV = os.environ.get("NATSRV") or os.path.join(ROOT, "natsrv")

TIMEOUT = 20.0        # default wait for a condition to become true
FAST = 2.0            # a healthy tunnel answers in well under this


# ---------------------------------------------------------------- util


class Failure(Exception):
	pass


class Skip(Exception):
	"""Raised by a test that cannot run here, e.g. one that needs
	privileges. The runner reports it as skipped, not failed."""


def free_port():
	while True:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.bind(("127.0.0.1", 0))
			port = s.getsockname()[1]
		finally:
			s.close()
		if port > 1024:
			return port


def wait_for(cond, timeout=TIMEOUT, interval=0.05, what="condition"):
	"""Poll cond() until it returns a true value or the timeout
	hits. Returns that value. Raises Failure with the name of the
	waited condition on timeout."""
	deadline = time.time() + timeout
	last = None
	while time.time() < deadline:
		last = cond()
		if last:
			return last
		time.sleep(interval)
	raise Failure("timeout after %.1fs waiting for %s (last=%r)"
	              % (timeout, what, last))


def wait_port(port, timeout=TIMEOUT):
	"""Wait until a connect to 127.0.0.1:port succeeds, then close."""
	def probe():
		try:
			socket.create_connection(("127.0.0.1", port), 0.2).close()
			return True
		except OSError:
			return False
	wait_for(probe, timeout, what="port %d to listen" % port)


def rst_sock(s):
	"""Close a socket with RST, no FIN, no TIME_WAIT drain."""
	try:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
		             struct.pack("ii", 1, 0))
	except OSError:
		pass
	try:
		s.close()
	except OSError:
		pass


def fin_sock(s):
	"""Close a socket with a normal FIN."""
	try:
		s.shutdown(socket.SHUT_RDWR)
	except OSError:
		pass
	try:
		s.close()
	except OSError:
		pass


def http_get(port, path="/", timeout=FAST, body_limit=100000):
	"""One HTTP/1.0 request over port. Returns (status, body).
	Raises OSError or Failure on a dead connection."""
	s = socket.create_connection(("127.0.0.1", port), timeout)
	try:
		s.settimeout(timeout)
		req = ("GET %s HTTP/1.0\r\nHost: natt\r\n\r\n" % path).encode()
		s.sendall(req)
		data = b""
		while len(data) < body_limit:
			chunk = s.recv(65536)
			if not chunk:
				break
			data += chunk
	finally:
		s.close()
	if not data.startswith(b"HTTP/1."):
		raise Failure("no HTTP answer on port %d, got %r" % (port, data[:60]))
	head, _, body = data.partition(b"\r\n\r\n")
	status = head.split(b"\r\n")[0].decode(errors="replace")
	return status, body


def dial_ready(port, attempts=60, delay=0.05):
	"""Connect to the public port and prove the path works by
	sending one byte and reading it back. A connection that arrives
	while the server has no spare is reset at once, so retry on
	OSError. Returns the open socket, ready for more traffic."""
	last = None
	for _ in range(attempts):
		try:
			s = socket.create_connection(("127.0.0.1", port), FAST)
		except OSError as exc:
			last = exc
			time.sleep(delay)
			continue
		try:
			s.settimeout(1.0)
			s.sendall(b"\x00")
			if s.recv(1) == b"\x00":
				s.settimeout(15)
				return s
		except OSError as exc:
			last = exc
		fin_sock(s)
		time.sleep(delay)
	raise Failure("public port %d never tunnelled a byte (%r)" % (port, last))


def wait_public_failure(port, timeout=3.0, interval=0.05):
	"""Drive the tunnel until a public request fails. Each attempt
	uses one spare, so a dead path is reported by the first or
	second attempt. Returns True on failure, False on timeout."""
	deadline = time.time() + timeout
	while time.time() < deadline:
		try:
			http_get(port, timeout=1.0)
		except (OSError, Failure):
			return True
		time.sleep(interval)
	return False


def http_ok(port, path="/", timeout=FAST):
	try:
		status, _ = http_get(port, path, timeout)
	except (OSError, Failure):
		return False
	return status.startswith("HTTP/1.0 200") or status.startswith("HTTP/1.1 200")


# ---------------------------------------------------------------- backends


class Backend:
	"""A threaded service on 127.0.0.1:port for the tunnel to reach.
	kind "http" answers every request with 200 and a fixed body.
	kind "echo" sends back every byte it reads."""

	def __init__(self, kind="http"):
		self.kind = kind
		self.port = free_port()
		self.sock = None
		self.thread = None
		self.running = False
		self.body = b"natt ok\n"
		self.conns = 0
		self.lock = threading.Lock()

	def start(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind(("127.0.0.1", self.port))
		s.listen(16)
		self.sock = s
		self.running = True
		self.thread = threading.Thread(target=self._accept, daemon=True)
		self.thread.start()
		return self

	def stop(self):
		self.running = False
		if self.sock:
			try:
				self.sock.close()
			except OSError:
				pass
			self.sock = None
		if self.thread:
			self.thread.join(2)
			self.thread = None

	def _accept(self):
		while self.running:
			try:
				c, _ = self.sock.accept()
			except OSError:
				return
			with self.lock:
				self.conns += 1
			threading.Thread(target=self._serve, args=(c,), daemon=True).start()

	def _serve(self, c):
		try:
			c.settimeout(30)
			first = c.recv(65536)
			if not first:
				return
			if first.startswith(b"GET ") or first.startswith(b"HEAD "):
				buf = first
				while b"\r\n\r\n" not in buf and len(buf) < 8192:
					d = c.recv(4096)
					if not d:
						break
					buf += d
				head = ("HTTP/1.0 200 OK\r\n"
				        "Content-Type: text/plain\r\n"
				        "Content-Length: %d\r\n"
				        "Connection: close\r\n\r\n" % len(self.body))
				c.sendall(head.encode() + self.body)
			else:
				# Echo everything, including the first chunk. The
				# write runs in its own thread: the caller may send
				# more than the socket buffers hold before it reads,
				# and a blocking sendall here would deadlock both
				# sides.
				out = [first]
				stop = threading.Event()

				def writer():
					i = 0
					while not stop.is_set():
						while i < len(out):
							try:
								c.sendall(out[i])
							except OSError:
								return
							i += 1
						stop.wait(0.005)

				t = threading.Thread(target=writer, daemon=True)
				t.start()
				while True:
					d = c.recv(65536)
					if not d:
						break
					out.append(d)
				stop.set()
				t.join(5)
		except OSError:
			pass
		finally:
			fin_sock(c)


# ---------------------------------------------------------------- fault proxy


class ProxyConn:
	def __init__(self, nid, csock, usock, owner):
		self.id = nid
		self.c = csock
		self.u = usock
		self.owner = owner
		self.frozen = False
		self.closed = False
		self.req = None    # request byte of the first client hello
		self.hello = b""
		self.thread = None

	def start(self):
		self.thread = threading.Thread(target=self._pump, daemon=True)
		self.thread.start()

	def _pump(self):
		socks = [self.c, self.u]
		try:
			while not self.closed:
				r, _, _ = select.select(socks, [], [], 0.05)
				if self.frozen:
					continue
				for a in r:
					b = self.u if a is self.c else self.c
					d = a.recv(65536)
					if not d:
						raise OSError(errno.ECONNRESET, "eof")
					if a is self.c:
						self.classify(d)
					b.sendall(d)
		except (OSError, ValueError):
			pass
		finally:
			self.close(rst=False)

	def classify(self, d):
		"""Learn the role from the client hello: frame header
		[type=2][len:2][eph 32][req][mac 32], so the request byte
		sits at offset 32 of the payload, 35 of the stream. A hello
		can be split, so keep the bytes until it is complete."""
		if self.req is not None:
			return
		self.hello += d
		if len(self.hello) >= 3 and self.hello[0] != 2:
			self.req = -1
			return
		if len(self.hello) > 35:
			self.req = self.hello[35]

	def close(self, rst=False):
		if self.closed:
			return
		self.closed = True
		for s in (self.c, self.u):
			if rst:
				rst_sock(s)
			else:
				fin_sock(s)


class FaultProxy:
	"""TCP relay in front of the server admin port. Every accepted
	connection gets an increasing id in accept order. A typical
	client makes two: control first, then the spare."""

	def __init__(self, listen_port):
		self.upstream = None
		self.port = listen_port
		self.sock = None
		self.thread = None
		self.running = False
		self.conns = []
		self.lock = threading.Lock()
		self.accepted = 0
		self.block_new = False

	def start(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind(("127.0.0.1", self.port))
		s.listen(16)
		self.sock = s
		self.running = True
		self.thread = threading.Thread(target=self._accept, daemon=True)
		self.thread.start()
		return self

	def stop(self):
		self.running = False
		if self.sock:
			try:
				self.sock.close()
			except OSError:
				pass
			self.sock = None
		with self.lock:
			conns = list(self.conns)
		for c in conns:
			c.close(rst=False)
		if self.thread:
			self.thread.join(2)
			self.thread = None

	def _accept(self):
		while self.running:
			try:
				c, _ = self.sock.accept()
			except OSError:
				return
			if self.block_new or self.upstream is None:
				rst_sock(c)
				continue
			try:
				u = socket.create_connection(("127.0.0.1", self.upstream), 2)
			except OSError:
				rst_sock(c)
				continue
			with self.lock:
				self.accepted += 1
				conn = ProxyConn(self.accepted, c, u, self)
				self.conns.append(conn)
			conn.start()

	def open(self):
		with self.lock:
			return [c for c in self.conns if not c.closed]

	def conn(self, nid):
		with self.lock:
			for c in self.conns:
				if c.id == nid:
					return c
		raise Failure("proxy has no connection %d (accepted %d)"
	              % (nid, self.accepted))

	def spare(self, timeout=TIMEOUT):
		"""The armed spare. Identified by the request byte of its
		handshake: 2 is an encrypted tunnel socket. Waits, because a
		fresh spare takes a round trip to appear."""
		def find():
			cands = [c for c in self.open() if c.req == 2]
			return cands[-1] if cands else None
		return wait_for(find, timeout, what="a spare through the proxy")

	def control(self, timeout=TIMEOUT):
		"""The control socket. Request byte 0."""
		def find():
			cands = [c for c in self.open() if c.req == 0]
			return cands[0] if cands else None
		return wait_for(find, timeout, what="a control socket through the proxy")

	def drop(self, nid, rst=True):
		"""Kill connection nid. rst=True for RST, False for FIN."""
		c = self.conn(nid)
		c.close(rst=rst)

	def freeze(self, nid):
		"""Stop forwarding on nid. Both sockets stay open, so both
		ends see a silent blackhole, not an error."""
		self.conn(nid).frozen = True

	def thaw(self, nid):
		self.conn(nid).frozen = False


# ---------------------------------------------------------------- nat pair


class Nat:
	"""One server process, one client process, one work dir."""

	def __init__(self, admin_port=None, public_port=None, local_port=None,
	             client_admin=None, extra_server=(), extra_client=(),
	             name="nat"):
		self.dir = tempfile.mkdtemp(prefix="natt-%s-" % name)
		self.admin = admin_port or free_port()
		self.public = public_port or free_port()
		self.local = local_port
		self.client_admin = client_admin or self.admin
		self.extra_server = list(extra_server)
		self.extra_client = list(extra_client)
		self.secret_file = os.path.join(self.dir, "secret.txt")
		self.key_file = os.path.join(self.dir, "server.key")
		self.server_log = os.path.join(self.dir, "server.log")
		self.client_log = os.path.join(self.dir, "client.log")
		self.server = None
		self.client = None
		self.server_in = None
		self.client_in = None
		with open(self.secret_file, "w") as f:
			f.write("natt-secret-%d\n" % os.getpid())
		os.chmod(self.secret_file, 0o600)
		out = subprocess.run([NATSRV, "--genkey", self.key_file],
		                     capture_output=True, text=True)
		if out.returncode != 0:
			raise Failure("--genkey failed: %s" % out.stderr)
		self.pubkey = ""
		with open(self.key_file) as f:
			self.pubkey = f.readline().strip()

	def start_server(self):
		self.server_in = open(self.server_log, "ab")
		self.server = subprocess.Popen(
			[NATSRV, "--mode", "server",
			 "--secret-file", self.secret_file,
			 "--server-key", self.key_file,
			 "--admin", "127.0.0.1:%d" % self.admin,
			 "--public", "127.0.0.1:%d" % self.public] + self.extra_server,
			stdout=self.server_in, stderr=self.server_in)
		wait_port(self.admin)
		wait_port(self.public)
		return self.server

	def start_client(self):
		self.client_in = open(self.client_log, "ab")
		self.client = subprocess.Popen(
			[NATSRV, "--mode", "client",
			 "--secret-file", self.secret_file,
			 "--server-pubkey", self.pubkey,
			 "--admin", "127.0.0.1:%d" % self.client_admin,
			 "--local", "127.0.0.1:%d" % self.local] + self.extra_client,
			stdout=self.client_in, stderr=self.client_in)
		return self.client

	def start_client_local(self, local_text, path):
		"""Start the client with --local as a unix socket path."""
		self.client_in = open(self.client_log, "ab")
		self.client = subprocess.Popen(
			[NATSRV, "--mode", "client",
			 "--secret-file", self.secret_file,
			 "--server-pubkey", self.pubkey,
			 "--admin", "127.0.0.1:%d" % self.client_admin,
			 "--local", path],
			stdout=self.client_in, stderr=self.client_in)
		return self.client

	def start(self):
		self.start_server()
		self.start_client()
		return self

	def stop_server(self, sig=None):
		if self.server and self.server.poll() is None:
			self.server.send_signal(sig or 15)
			try:
				self.server.wait(5)
			except subprocess.TimeoutExpired:
				self.server.kill()
				self.server.wait(5)

	def stop_client(self, sig=None):
		if self.client and self.client.poll() is None:
			self.client.send_signal(sig or 15)
			try:
				self.client.wait(5)
			except subprocess.TimeoutExpired:
				self.client.kill()
				self.client.wait(5)

	def stop(self):
		self.stop_client()
		self.stop_server()
		for f in (self.server_in, self.client_in):
			if f:
				f.close()
		self.server_in = self.client_in = None

	def cleanup(self):
		self.stop()
		shutil.rmtree(self.dir, ignore_errors=True)

	def read(self, path):
		try:
			with open(path, "rb") as f:
				return f.read().decode(errors="replace")
		except OSError:
			return ""

	def slog(self):
		return self.read(self.server_log)

	def clog(self):
		return self.read(self.client_log)

	def alive(self):
		"""True while both processes are up."""
		return (self.server is not None and self.server.poll() is None
		        and self.client is not None and self.client.poll() is None)

	def wait_tunnel(self, timeout=TIMEOUT):
		"""Wait until a public HTTP request works end to end."""
		return wait_for(lambda: http_ok(self.public), timeout,
		                what="a working tunnel on public port %d" % self.public)

	def wait_log(self, which, needle, timeout=TIMEOUT):
		path = self.server_log if which == "server" else self.client_log
		return wait_for(lambda: needle in self.read(path), timeout,
		                what="%r in the %s log" % (needle, which))

	def count_log(self, which, needle):
		path = self.server_log if which == "server" else self.client_log
		return self.read(path).count(needle)


# ---------------------------------------------------------------- tests

TESTS = []


def test(fn):
	TESTS.append(fn)
	return fn


def slow(fn):
	fn.slow = True
	TESTS.append(fn)
	return fn


@test
def tunnel_basic(ctx):
	"""A public request reaches the local service and returns 200."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port).start()
	nat.wait_tunnel()
	for i in range(3):
		status, body = http_get(nat.public)
		if not status.endswith("200 OK"):
			raise Failure("request %d: %s" % (i, status))
		if body != be.body:
			raise Failure("body mismatch: %r" % body[:40])
	if "OK (admin)" not in nat.slog():
		raise Failure("server did not log the admin handshake:\n" + nat.slog())


@test
def data_integrity(ctx):
	"""400 KiB in and back over one tunnel, byte for byte."""
	be = Backend("echo").start()
	nat = ctx.nat(local=be.port).start()
	wait_for(lambda: "OK (admin)" in nat.slog(), what="admin handshake")
	payload = bytes(range(256)) * 1600
	s = dial_ready(nat.public)
	try:
		send = threading.Thread(target=s.sendall, args=(payload,), daemon=True)
		send.start()
		got = b""
		while len(got) < len(payload):
			d = s.recv(65536)
			if not d:
				break
			got += d
		send.join(15)
	finally:
		fin_sock(s)
	if got != payload:
		raise Failure("echo mismatch, sent %d got %d" % (len(payload), len(got)))


@test
def data_before_conn(ctx):
	"""Data that reaches the spare before the CONN frame must not kill
	the tunnel. The server pairs the spare first and writes CONN to
	the control socket second, so a readable spare is normal. The
	fault proxy freezes the control socket to force that order."""
	be = Backend("echo").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	ctrl = proxy.control()
	proxy.freeze(ctrl.id)
	payload = bytes(range(256)) * 400          # 100 KiB, one burst
	s = None
	try:
		s = socket.create_connection(("127.0.0.1", nat.public), FAST)
		s.settimeout(10)
		s.sendall(payload)
		# The tunnel data is now queued on the client spare, and the
		# CONN frame is still held by the proxy.
		time.sleep(0.4)
		proxy.thaw(ctrl.id)
		got = b""
		while len(got) < len(payload):
			d = s.recv(65536)
			if not d:
				break
			got += d
	finally:
		proxy.thaw(ctrl.id)
		if s:
			fin_sock(s)
	if got != payload:
		raise Failure("tunnel died with data queued before CONN: "
		              "sent %d got %d" % (len(payload), len(got)))


@test
def spare_rst(ctx):
	"""RST on the spare: the client re-arms it on its own tick, with
	no public traffic and no restart."""
	be = Backend("http").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	spare = proxy.spare()
	proxy.drop(spare.id, rst=True)
	wait_for(lambda: "spare socket dead, re-arming" in nat.clog()
	         or "lost spare upstream socket" in nat.slog(),
	         what="the spare loss to be noticed")
	if not nat.alive():
		raise Failure("a process died on spare loss")
	# No public traffic at all: a new spare must appear by itself.
	wait_for(lambda: proxy.spare().id > spare.id, what="a new spare connection")
	nat.wait_tunnel()


@test
def spare_fin(ctx):
	"""Orderly close of the spare: same recovery as an RST."""
	be = Backend("http").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	spare = proxy.spare()
	proxy.drop(spare.id, rst=False)
	wait_for(lambda: proxy.spare().id > spare.id, what="a new spare connection")
	nat.wait_tunnel()


@test
def public_without_spare(ctx):
	"""A public connection that arrives while the server has no spare
	is reset at once, not left hanging, and the tunnel recovers."""
	be = Backend("http").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	spare = proxy.spare()
	proxy.block_new = True
	proxy.drop(spare.id, rst=True)
	nat.wait_log("server", "lost spare upstream socket")
	t0 = time.time()
	try:
		status, _ = http_get(nat.public, timeout=3.0)
		raise Failure("public request succeeded with no spare: %s" % status)
	except (OSError, Failure) as exc:
		if isinstance(exc, Failure) and "succeeded" in str(exc):
			raise
	elapsed = time.time() - t0
	if elapsed > 1.5:
		raise Failure("public connection hung %.2fs instead of failing fast"
		              % elapsed)
	proxy.block_new = False
	nat.wait_tunnel()


@test
def control_rst(ctx):
	"""RST on the control socket: the client reconnects and the tunnel
	heals."""
	be = Backend("http").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	proxy.drop(proxy.control().id, rst=True)
	nat.wait_log("client", "lost control socket, reconnecting")
	nat.wait_log("server", "lost control socket")
	nat.wait_tunnel()


@test
def control_fin(ctx):
	"""Orderly close of the control socket: detected and replaced."""
	be = Backend("http").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	proxy.drop(proxy.control().id, rst=False)
	nat.wait_log("client", "lost control socket, reconnecting")
	nat.wait_tunnel()


@test
def control_and_spare_rst(ctx):
	"""Both control and spare die at once: full re-handshake."""
	be = Backend("http").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	spare = proxy.spare()
	control = proxy.control()
	proxy.drop(control.id, rst=True)
	proxy.drop(spare.id, rst=True)
	wait_for(lambda: len(proxy.open()) >= 2 and proxy.spare().id > spare.id,
	         what="a fresh control and spare")
	nat.wait_tunnel()


@test
def server_restart(ctx):
	"""Server killed and restarted: the client re-handshakes alone."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port).start()
	nat.wait_tunnel()
	nat.stop_server(sig=9)
	wait_for(lambda: not http_ok(nat.public, timeout=1.0),
	         what="the public port to stop answering")
	nat.start_server()
	wait_for(lambda: "connect upstream" in nat.clog()
	         or "lost control socket" in nat.clog(),
	         what="the client to notice the dead server")
	nat.wait_tunnel()


@test
def client_restart(ctx):
	"""Client killed and restarted: it takes over the control socket
	and the tunnel heals."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port).start()
	nat.wait_tunnel()
	nat.stop_client(sig=9)
	nat.start_client()
	nat.wait_tunnel()
	if "OK (admin)" not in nat.slog():
		raise Failure("no admin handshake in the server log")


@test
def local_service_down(ctx):
	"""Local service unreachable: the client logs it, drops the paired
	spare, arms a new one, and the next request works when the
	service is back."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port).start()
	nat.wait_tunnel()
	be.stop()
	if not wait_public_failure(nat.public):
		raise Failure("the public side still answered after the backend died")
	nat.wait_log("client", "connect local")
	if not nat.alive():
		raise Failure("a process died when the local service was down")
	be.start()
	wait_for(lambda: http_ok(nat.public, timeout=FAST), timeout=TIMEOUT,
	         what="the tunnel to recover after the service came back")


@test
def scanner_burst(ctx):
	"""Drive-by scanners on the admin port never drop a live control
	socket."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port).start()
	nat.wait_tunnel()

	def scan(n):
		for _ in range(n):
			try:
				s = socket.create_connection(("127.0.0.1", nat.admin), 1)
				s.recv(64)                            # server hello
				s.sendall(b"\x02\x00A" + b"x" * 32)   # bogus hello
				s.close()
			except OSError:
				pass

	threads = [threading.Thread(target=scan, args=(6,)) for _ in range(3)]
	for t in threads:
		t.start()
	for t in threads:
		t.join()
	if not nat.alive():
		raise Failure("a process died during the scanner burst")
	control_lost = nat.count_log("server", "lost control socket")
	if control_lost:
		raise Failure("scanners dropped the control socket (%d times)"
		              % control_lost)
	if nat.count_log("server", "rejected!") == 0:
		raise Failure("the server did not reject the bogus hellos")
	nat.wait_tunnel()


@test
def scanner_silent(ctx):
	"""A peer that connects and sends nothing is dropped after the
	hello deadline, and the tunnel keeps working."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port).start()
	nat.wait_tunnel()
	s = socket.create_connection(("127.0.0.1", nat.admin), 2)
	try:
		s.recv(200)          # server hello, then stay silent
		s.settimeout(6)
		dropped = False
		try:
			data = s.recv(100)
			dropped = data == b""
		except ConnectionResetError:
			dropped = True
		if not dropped:
			raise Failure("server did not drop the silent peer")
	finally:
		fin_sock(s)
	if not nat.alive():
		raise Failure("a process died on a silent peer")
	nat.wait_tunnel()


@test
def wrong_secret(ctx):
	"""A client without the shared secret cannot take over a live
	control socket."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port).start()
	nat.wait_tunnel()
	other = Nat(local_port=be.port, admin_port=nat.admin,
	            public_port=free_port(), name="wrong")
	ctx.objs.append(other)
	other.pubkey = nat.pubkey
	with open(other.secret_file, "w") as f:
		f.write("wrong-secret\n")
	other.start_client()
	time.sleep(0.5)
	other.stop_client()
	if "rejected!" not in nat.slog():
		raise Failure("the server accepted a wrong secret")
	if not nat.alive():
		raise Failure("a process died on a wrong secret")
	nat.wait_tunnel()


@test
def timeout_kills_redirect(ctx):
	"""--timeout fires on a stalled tunnel while the control channel
	and both processes stay up."""
	be = Backend("http").start()
	nat = ctx.nat(local=be.port, extra_server=("--timeout", "2")).start()
	nat.wait_tunnel()
	s = socket.create_connection(("127.0.0.1", nat.public), FAST)
	s.sendall(b"GET / HTTP/1.0\r\n\r\n")
	time.sleep(4)
	fin_sock(s)
	if not nat.alive():
		raise Failure("a process died on a tunnel timeout")
	nat.wait_tunnel()


@test
def unix_local_socket(ctx):
	"""--local can be a unix socket path instead of host:port."""
	sockdir = tempfile.mkdtemp(prefix="natt-unix-")
	path = os.path.join(sockdir, "s.sock")
	be = Backend("http")
	srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	srv.bind(path)
	srv.listen(8)

	def serve():
		while True:
			try:
				c, _ = srv.accept()
			except OSError:
				return
			c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n"
			          b"Connection: close\r\n\r\nunix\n")
			fin_sock(c)

	threading.Thread(target=serve, daemon=True).start()
	try:
		nat = ctx.nat(local=be.port).start()
		nat.stop_client()
		nat.start_client_local("127.0.0.1:%d" % 0, path)
		nat.wait_tunnel()
	finally:
		srv.close()
		shutil.rmtree(sockdir, ignore_errors=True)


@slow
def control_blackhole(ctx):
	"""A control socket that silently stops forwarding (no FIN, no
	RST) is caught by the TCP keepalive probes, and the client
	reconnects."""
	be = Backend("http").start()
	nat, proxy = ctx.pair(local=be.port)
	nat.wait_tunnel()
	ctrl = proxy.control()
	dport = ctrl.owner.upstream
	if os.geteuid() != 0 or not shutil.which("iptables"):
		raise Skip("needs root and iptables to blackhole loopback packets")
	cport = ctrl.u.getsockname()[1]
	rule_in = ["-p", "tcp", "-i", "lo", "-s", "127.0.0.1", "--sport",
	           str(dport), "--dport", str(cport), "-j", "DROP"]
	rule_out = ["-p", "tcp", "-o", "lo", "-d", "127.0.0.1", "--sport",
	            str(cport), "--dport", str(dport), "-j", "DROP"]
	subprocess.run(["iptables", "-I", "INPUT", "1"] + rule_in, check=True)
	subprocess.run(["iptables", "-I", "OUTPUT", "1"] + rule_out, check=True)
	try:
		nat.wait_log("client", "lost control socket, reconnecting",
		             timeout=120)
	finally:
		subprocess.run(["iptables", "-D", "INPUT"] + rule_in)
		subprocess.run(["iptables", "-D", "OUTPUT"] + rule_out)
	nat.wait_tunnel(timeout=60)


# ---------------------------------------------------------------- runner


class Ctx:
	def __init__(self):
		self.objs = []

	def nat(self, local, extra_server=(), extra_client=(), name="nat",
	        client_admin=None):
		n = Nat(local_port=local, extra_server=extra_server,
		        extra_client=extra_client, name=name,
		        client_admin=client_admin)
		self.objs.append(n)
		return n

	def proxy_port(self, upstream_port=None):
		"""A fault proxy for the admin port. Pass the server admin
		port when it is already known, or set proxy.upstream before
		the client starts."""
		p = FaultProxy(free_port())
		p.upstream = upstream_port
		p.start()
		self.objs.append(_Stop(p))
		return p

	def pair(self, local, extra_server=(), extra_client=(), name="nat"):
		"""A proxy in front of the server admin port, plus one
		server and one client that reaches the server through it."""
		p = self.proxy_port()
		n = self.nat(local=local, extra_server=extra_server,
		             extra_client=extra_client, name=name,
		             client_admin=p.port)
		p.upstream = n.admin
		n.start()
		return n, p

	def close(self):
		for o in reversed(self.objs):
			try:
				if isinstance(o, Nat):
					o.cleanup()
				else:
					o.stop()
			except Exception:
				pass
		self.objs = []


class _Stop:
	def __init__(self, obj):
		self.obj = obj

	def stop(self):
		self.obj.stop()


def main(argv):
	want_slow = os.environ.get("NATT_SLOW") == "1"
	if "--list" in argv:
		for fn in TESTS:
			mark = " (slow)" if getattr(fn, "slow", False) else ""
			doc = (fn.__doc__ or "").strip().split("\n")[0]
			print("%-24s %s%s" % (fn.__name__, doc, mark))
		return 0
	names = [a for a in argv[1:] if not a.startswith("-")]
	os.makedirs("/tmp/natt", exist_ok=True)
	if not os.access(NATSRV, os.X_OK):
		print("error: %s is missing, run make first" % NATSRV)
		return 2
	selected = []
	for fn in TESTS:
		if names and fn.__name__ not in names:
			continue
		if getattr(fn, "slow", False) and not want_slow and not names:
			continue
		selected.append(fn)
	failed = []
	skipped = []
	started = time.time()
	for fn in selected:
		ctx = Ctx()
		t0 = time.time()
		sys.stdout.write("%-24s " % fn.__name__)
		sys.stdout.flush()
		try:
			fn(ctx)
			print("ok    %5.2fs" % (time.time() - t0))
		except Skip as exc:
			print("skip  %s" % exc)
			skipped.append(fn.__name__)
		except Exception as exc:
			print("FAIL  %5.2fs" % (time.time() - t0))
			print("  %s: %s" % (type(exc).__name__, exc))
			if not isinstance(exc, Failure):
				traceback.print_exc()
			failed.append(fn.__name__)
			for o in ctx.objs:
				if isinstance(o, Nat):
					print("  server log tail:")
					for line in o.slog().splitlines()[-8:]:
						print("    " + line)
					print("  client log tail:")
					for line in o.clog().splitlines()[-8:]:
						print("    " + line)
		finally:
			ctx.close()
	total = time.time() - started
	if failed:
		print("\n%d of %d tests failed: %s" % (len(failed), len(selected),
		                                       " ".join(failed)))
		return 1
	msg = "\nall %d tests passed in %.1fs" % (len(selected) - len(skipped), total)
	if skipped:
		msg += " (%d skipped: %s)" % (len(skipped), " ".join(skipped))
	print(msg)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
