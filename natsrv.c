#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#include <linux/random.h>
#endif
#include "sha256.h"

#define NONCE_LEN 8
#define NONCE_HEX_LEN (NONCE_LEN*2)
#define HASH_HEX_LEN (SHA256_DIGEST_SIZE*2)
#define BUFSZ 1024
/* Fixed per-thread stack size, ported from microsocks. The
   microsocks ifdeffery (PTHREAD_STACK_MIN, per-OS overrides)
   is dropped: 64KB is enough for the tunnel thread on any
   OS, whose biggest stack user is getaddrinfo in libc. */
#define THREAD_STACK_SIZE (64*1024)

static const char *g_secret;
static size_t g_secret_len;

static void print_timestamp(void) {
	time_t t = time(NULL);
	struct tm tmv;
	localtime_r(&t, &tmv);
	char buf[64];
	size_t n = strftime(buf, sizeof buf, "[%Y-%m-%d %H:%M:%S] ", &tmv);
	if(n) fwrite(buf, 1, n, stdout);
	fflush(stdout);
}

static const char hexd[] = "0123456789abcdef";

static void hex_encode(const unsigned char *in, size_t n, char *out) {
	size_t i;
	for(i=0;i<n;i++) {
		out[2*i] = hexd[(in[i]>>4)&15];
		out[2*i+1] = hexd[in[i]&15];
	}
	out[2*n] = 0;
}

static void get_nonce(char out[NONCE_HEX_LEN+1]) {
	unsigned char raw[NONCE_LEN];

#ifdef HAVE_GETRANDOM
	/* getrandom() syscall via libc (Linux 3.17+ / glibc 2.25+).
	   Enable with: make CPPFLAGS=-DHAVE_GETRANDOM */
	{
		ssize_t r;
		size_t got = 0;
		while(got < NONCE_LEN) {
			r = getrandom(raw+got, NONCE_LEN-got, 0);
			if(r < 0) {
				if(errno == EINTR) continue;
				perror("getrandom");
				exit(1);
			}
			if(r == 0) break;
			got += (size_t)r;
		}
		if(got != NONCE_LEN) {
			perror("getrandom");
			exit(1);
		}
	}
#else
	int fd = open("/dev/urandom", 0);
	if(fd >= 0) {
		size_t got = 0;
		while(got < NONCE_LEN) {
			ssize_t r = read(fd, raw+got, NONCE_LEN-got);
			if(r <= 0) break;
			got += (size_t)r;
		}
		close(fd);
		if(got != NONCE_LEN) {
			/* No fallback: rand() seeded with time+pid is
			   predictable and not secure. Fail closed. */
			perror("read /dev/urandom");
			exit(1);
		}
	} else {
		perror("open /dev/urandom");
		exit(1);
	}
#endif
	hex_encode(raw, NONCE_LEN, out);
}

static void compute_hash(const char *cmd, const char *nonce, char out[HASH_HEX_LEN+1]) {
	sha256_ctx ctx;
	unsigned char digest[SHA256_DIGEST_SIZE];
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char*)cmd, strlen(cmd));
	sha256_update(&ctx, (const unsigned char*)g_secret, g_secret_len);
	sha256_update(&ctx, (const unsigned char*)nonce, strlen(nonce));
	sha256_final(&ctx, digest);
	hex_encode(digest, SHA256_DIGEST_SIZE, out);
}

/* Constant-time compare (matches py hmac.compare_digest fix).
   Old code used memcmp, which short-circuits and leaks how
   many leading bytes matched. */
static int ct_equal(const char *a, const char *b, size_t n) {
	unsigned char diff = 0;
	size_t i;
	for(i=0;i<n;i++) diff |= (unsigned char)(a[i] ^ b[i]);
	return diff == 0;
}

/* sk2 stream cipher: SHA256 in counter mode, per tunnel, per
   direction. Mirrors the Python _CtrStream / _enc_keys exactly:
   key = sha256(label + secret + nonce), label "enc-up" or
   "enc-dn"; block i = sha256(key + be64(i)); data XOR keystream.
   State (counter + leftover) is continuous across chunks. */
struct ctr_stream {
	unsigned char key[SHA256_DIGEST_SIZE];
	unsigned long long counter;
	unsigned char leftover[SHA256_DIGEST_SIZE];
	size_t leftover_len;
};

static void ctr_init(struct ctr_stream *st, const char *label, const char *nonce) {
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char*)label, strlen(label));
	sha256_update(&ctx, (const unsigned char*)g_secret, g_secret_len);
	sha256_update(&ctx, (const unsigned char*)nonce, strlen(nonce));
	sha256_final(&ctx, st->key);
	st->counter = 0;
	st->leftover_len = 0;
}

static void ctr_crypt(struct ctr_stream *st, unsigned char *data, size_t n) {
	size_t pos = 0;
	while(pos < n) {
		if(st->leftover_len == 0) {
			unsigned char ctrbe[8];
			unsigned long long c = st->counter++;
			int i;
			for(i=0;i<8;i++) ctrbe[i] = (unsigned char)(c >> (56 - 8*i));
			sha256_ctx ctx;
			sha256_init(&ctx);
			sha256_update(&ctx, st->key, SHA256_DIGEST_SIZE);
			sha256_update(&ctx, ctrbe, 8);
			sha256_final(&ctx, st->leftover);
			st->leftover_len = SHA256_DIGEST_SIZE;
		}
		if(st->leftover_len < n - pos) {
			size_t i;
			for(i=0;i<st->leftover_len;i++) data[pos+i] ^= st->leftover[i];
			pos += st->leftover_len;
			st->leftover_len = 0;
		} else {
			size_t take = n - pos;
			size_t i;
			for(i=0;i<take;i++) data[pos+i] ^= st->leftover[i];
			memmove(st->leftover, st->leftover+take, st->leftover_len-take);
			st->leftover_len -= take;
			pos += take;
		}
	}
}

static int send_all(int fd, const void *buf, size_t len) {
	const char *p = buf;
	size_t sent = 0;
	while(sent < len) {
		ssize_t n = send(fd, p+sent, len-sent, 0);
		if(n < 0) {
			if(errno == EINTR) continue;
			return -1;
		}
		if(n == 0) return -1;
		sent += (size_t)n;
	}
	return 0;
}

static int recv_exact(int fd, void *buf, size_t len) {
	char *p = buf;
	size_t got = 0;
	while(got < len) {
		ssize_t n = recv(fd, p+got, len-got, 0);
		if(n < 0) {
			if(errno == EINTR) continue;
			return -1;
		}
		if(n == 0) return -1;
		got += (size_t)n;
	}
	return 0;
}

static int recv_line(int fd, char *buf, size_t cap, size_t *out_len) {
	size_t n = 0;
	while(n + 1 < cap) {
		char c;
		ssize_t r = recv(fd, &c, 1, 0);
		if(r < 0) {
			if(errno == EINTR) continue;
			return -1;
		}
		if(r == 0) return -1;
		buf[n++] = c;
		if(c == '\n') break;
	}
	buf[n] = 0;
	if(out_len) *out_len = n;
	return 0;
}

/* resolve host like microsocks/server.c resolve(), but without AI_PASSIVE
   for client connections and with it for listen sockets. */
static int resolve_host(const char *host, unsigned short port, int passive, struct addrinfo **out) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if(passive) hints.ai_flags = AI_PASSIVE;
	char port_buf[8];
	snprintf(port_buf, sizeof port_buf, "%u", (unsigned)port);
	return getaddrinfo(host, port_buf, &hints, out);
}

/* Address handling: explicit numeric literals win. A numeric v4
   literal gives v4, a numeric v6 literal gives v6. For host names
   we prefer v4 and fall back to v6 (matches py _resolve default
   want_v4=False ordering after the fix; connect tries every
   result in turn). Listen sockets use the resolved family. */
union sockaddr_union {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

static int is_numeric_v4(const char *ip) {
	unsigned int a,b,c,d;
	char extra;
	if(sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return 0;
	return a < 256 && b < 256 && c < 256 && d < 256;
}

static int is_numeric_v6(const char *ip) {
	struct in6_addr addr;
	return inet_pton(AF_INET6, ip, &addr) == 1;
}

static int resolve_any(const char *host, unsigned short port, int passive, struct addrinfo **out) {
	/* Numeric literal fast path: build a one-result list via
	   getaddrinfo on the literal itself (no DNS), so callers
	   get a uniform addrinfo to iterate. */
	if(is_numeric_v4(host) || is_numeric_v6(host)) {
		struct addrinfo hints;
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if(passive) hints.ai_flags = AI_PASSIVE;
		char port_buf[8];
		snprintf(port_buf, sizeof port_buf, "%u", (unsigned)port);
		return getaddrinfo(host, port_buf, &hints, out);
	}
	return resolve_host(host, port, passive, out);
}

/* Pick the best addrinfo: first v4 wins, otherwise first v6.
   This keeps v4 preferred for host names while allowing v6. */
static struct addrinfo *pick_best(struct addrinfo *ai) {
	struct addrinfo *p;
	for(p = ai; p; p = p->ai_next)
		if(p->ai_family == AF_INET) return p;
	for(p = ai; p; p = p->ai_next)
		if(p->ai_family == AF_INET6) return p;
	return 0;
}

static int connect_to(const char *host, unsigned short port) {
	struct addrinfo *ai = 0;
	if(resolve_any(host, port, 0, &ai) < 0) return -1;
	/* Try every result in turn (v4 first via pick order is not
	   enough alone: a dead v4 must not block a live v6). */
	struct addrinfo *order[2];
	order[0] = pick_best(ai);
	order[1] = 0;
	if(order[0]) {
		struct addrinfo *p;
		for(p = ai; p; p = p->ai_next)
			if(p != order[0] && !order[1]) order[1] = p;
	}
	int fd = -1;
	int i;
	for(i=0;i<2;i++) {
		struct addrinfo *sel = order[i];
		if(!sel) continue;
		fd = socket(sel->ai_family, sel->ai_socktype, sel->ai_protocol);
		if(fd < 0) continue;
		if(connect(fd, sel->ai_addr, sel->ai_addrlen) == 0) break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(ai);
	return fd;
}

static int listen_on(const char *host, unsigned short port) {
	struct addrinfo *ai = 0;
	if(resolve_any(host, port, 1, &ai) < 0) return -1;
	struct addrinfo *sel = pick_best(ai);
	if(!sel) { freeaddrinfo(ai); return -1; }
	int fd = socket(sel->ai_family, sel->ai_socktype, sel->ai_protocol);
	if(fd < 0) { freeaddrinfo(ai); return -1; }
	int yes = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
	if(sel->ai_family == AF_INET6) {
		int v6only = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
	}
	int rc = bind(fd, sel->ai_addr, sel->ai_addrlen);
	if(rc == 0) rc = listen(fd, 1);
	freeaddrinfo(ai);
	if(rc < 0) { close(fd); return -1; }
	return fd;
}

static void format_addr(const union sockaddr_union *a, char *out, size_t cap) {
	char ip[INET6_ADDRSTRLEN];
	if(a->v4.sin_family == AF_INET6) {
		const char *s = inet_ntop(AF_INET6, &a->v6.sin6_addr, ip, sizeof ip);
		if(!s) s = "?";
		/* Wire format for v6 is [addr]:port, matching py fix. */
		snprintf(out, cap, "[%s]:%u", s, (unsigned)ntohs(a->v6.sin6_port));
	} else {
		const char *s = inet_ntop(AF_INET, &a->v4.sin_addr, ip, sizeof ip);
		if(!s) s = "?";
		snprintf(out, cap, "%s:%u", s, (unsigned)ntohs(a->v4.sin_port));
	}
}

struct tunnel {
	int fds;
	int fdc;
	pthread_t pt;
	volatile int done;
	int enc; /* 0 = cleartext skt, 1 = encrypted sk2 */
	struct ctr_stream enc_up; /* fds -> fdc */
	struct ctr_stream enc_dn; /* fdc -> fds */
};

/* Tunnel threads are heap allocated and the list stores pointers to
   them (microsocks pattern). The old code stored structs by value in
   a realloc'd array and passed &threads[i] to the thread: a later
   realloc could move the array, and the reap loop's swap-with-last
   copy could overwrite an element, so a running thread wrote done
   and fds through a stale or moved pointer. See tunnel_add,
   tunnel_reap and tunnel_start below. */
static void *tunnel_thread(void *data) {
	struct tunnel *t = data;
	int open0 = 1, open1 = 1;
	struct pollfd fds[2];
	fds[0].fd = t->fds; fds[0].events = POLLIN; fds[0].revents = 0;
	fds[1].fd = t->fdc; fds[1].events = POLLIN; fds[1].revents = 0;
	while(open0 || open1) {
		fds[0].fd = open0 ? t->fds : -1;
		fds[1].fd = open1 ? t->fdc : -1;
		int r = poll(fds, 2, -1);
		if(r < 0) {
			if(errno == EINTR) continue;
			break;
		}
		if(!((fds[0].revents | fds[1].revents) & (POLLIN|POLLERR|POLLHUP|POLLNVAL))) break;
		int infd = (fds[0].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)) ? t->fds : t->fdc;
		int outfd = (infd == t->fds) ? t->fdc : t->fds;
		if(!(fds[0].revents & POLLIN) && !(fds[1].revents & POLLIN)) {
			if(infd == t->fds) open0 = 0;
			else open1 = 0;
			shutdown(outfd, SHUT_WR);
			continue;
		}
		char buf[BUFSZ];
		ssize_t n = recv(infd, buf, sizeof buf, 0);
		if(n < 0) {
			if(errno == EINTR) continue;
			n = 0;
		}
		if(n == 0) {
			if(infd == t->fds) open0 = 0;
			else open1 = 0;
			shutdown(outfd, SHUT_WR);
			continue;
		}
		if(t->enc) {
			/* Same direction mapping as Python: enc_up is
			   fds->fdc, enc_dn is fdc->fds on both ends. */
			if(infd == t->fds) ctr_crypt(&t->enc_up, (unsigned char*)buf, (size_t)n);
			else ctr_crypt(&t->enc_dn, (unsigned char*)buf, (size_t)n);
		}
		size_t sent = 0;
		int failed = 0;
		while(sent < (size_t)n) {
			ssize_t m = send(outfd, buf+sent, (size_t)n-sent, 0);
			if(m < 0) {
				if(errno == EINTR) continue;
				failed = 1;
				break;
			}
			if(m == 0) { failed = 1; break; }
			sent += (size_t)m;
		}
		if(failed) break;
	}
	if(t->fdc >= 0) close(t->fdc);
	if(t->fds >= 0) close(t->fds);
	t->fdc = -1;
	t->fds = -1;
	t->done = 1;
	return 0;
}

static int tunnel_start(struct tunnel **slot, int fds, int fdc, int enc, const char *nonce) {
	struct tunnel *t = malloc(sizeof *t);
	if(!t) return -1;
	t->fds = fds;
	t->fdc = fdc;
	t->done = 0;
	t->enc = enc;
	if(enc) {
		ctr_init(&t->enc_up, "enc-up", nonce);
		ctr_init(&t->enc_dn, "enc-dn", nonce);
	}
	/* Ported from microsocks sockssrv.c: pthread_attr with a
	   fixed stack size. If attr init fails we fall back to
	   the default attr, same as microsocks. */
	pthread_attr_t *a = 0, attr;
	if(pthread_attr_init(&attr) == 0) {
		a = &attr;
		pthread_attr_setstacksize(a, THREAD_STACK_SIZE);
	}
	int rc = pthread_create(&t->pt, a, tunnel_thread, t);
	if(a) pthread_attr_destroy(&attr);
	if(rc != 0) {
		free(t);
		return -1;
	}
	*slot = t;
	return 0;
}

static void tunnel_reap(struct tunnel ***arr, size_t *count) {
	size_t i = 0;
	while(i < *count) {
		struct tunnel *t = (*arr)[i];
		if(t->done) {
			pthread_join(t->pt, 0);
			(*arr)[i] = (*arr)[*count - 1];
			(*count)--;
			free(t);
		} else i++;
	}
}

static int tunnel_add(struct tunnel ***arr, size_t *count, size_t *cap, int fds, int fdc, int enc, const char *nonce) {
	if(*count == *cap) {
		size_t ncap = *cap ? *cap * 2 : 8;
		struct tunnel **nt = realloc(*arr, ncap * sizeof *nt);
		if(!nt) return -1;
		*arr = nt;
		*cap = ncap;
	}
	if(tunnel_start(&(*arr)[*count], fds, fdc, enc, nonce) != 0) return -1;
	(*count)++;
	return 0;
}

/* ---- NAT client ---- */

static int client_setup_sock(const char *upstream_ip, unsigned short upstream_port, const char *cmd, char *nonce_out) {
	int fd = connect_to(upstream_ip, upstream_port);
	if(fd < 0) {
		perror("connect upstream");
		return -1;
	}
	char linebuf[NONCE_HEX_LEN + 2];
	/* python: sock.recv(NONCE_LEN*2+1).rstrip(b'\n') via Rocksock.recv(count) which
	   reads exactly count bytes or raises on EOF. The server sends nonce + '\n'. */
	if(recv_exact(fd, linebuf, NONCE_HEX_LEN + 1) < 0) {
		perror("recv nonce");
		close(fd);
		return -1;
	}
	linebuf[NONCE_HEX_LEN + 1] = 0;
	/* strip trailing newline(s) like rstrip(b'\n') - nonce is hex, safe */
	size_t nl = NONCE_HEX_LEN;
	while(nl > 0 && linebuf[nl] == '\n') { linebuf[nl] = 0; nl--; }
	char expect[HASH_HEX_LEN + 1];
	compute_hash(cmd, linebuf, expect);
	/* hash + '\n' */
	char out[HASH_HEX_LEN + 2];
	memcpy(out, expect, HASH_HEX_LEN);
	out[HASH_HEX_LEN] = '\n';
	out[HASH_HEX_LEN+1] = 0;
	if(send_all(fd, out, HASH_HEX_LEN + 1) < 0) {
		perror("send hash");
		close(fd);
		return -1;
	}
	if(nonce_out) strcpy(nonce_out, linebuf);
	return fd;
}

static void client_doit(const char *upstream_ip, unsigned short upstream_port, const char *local_ip, unsigned short local_port) {
	char next_nonce[NONCE_HEX_LEN+1];
	int control = client_setup_sock(upstream_ip, upstream_port, "adm", 0);
	if(control < 0) return;
	int next = client_setup_sock(upstream_ip, upstream_port, "sk2", next_nonce);
	if(next < 0) { close(control); return; }
	struct tunnel **threads = 0;
	size_t nthreads = 0, capthreads = 0;
	while(1) {
		tunnel_reap(&threads, &nthreads);
		char line[4096];
		size_t linelen = 0;
		if(recv_line(control, line, sizeof line, &linelen) < 0 || !linelen || line[linelen-1] != '\n') {
			/* Lost control (matches py fix): old C code broke out
			   and exited, killing all tunnels. Tear down control+
			   spare and re-handshake with backoff. */
			printf("lost control socket, reconnecting\n");
			fflush(stdout);
			close(control);
			if(next >= 0) close(next);
			next = -1;
			control = -1;
			while(control < 0) {
				struct timespec ts;
				ts.tv_sec = 2;
				ts.tv_nsec = 0;
				nanosleep(&ts, 0);
				control = client_setup_sock(upstream_ip, upstream_port, "adm", 0);
				if(control < 0) continue;
				next = client_setup_sock(upstream_ip, upstream_port, "sk2", next_nonce);
				if(next < 0) { close(control); control = -1; }
			}
			continue;
		}
		print_timestamp();
		fputs(line, stdout);
		if(linelen && line[linelen-1] != '\n') fputc('\n', stdout);
		fflush(stdout);
		if(strncmp(line, "CONN:", 5) == 0) {
			/* Parse CONN:ip:port or CONN:[v6]:port (matches py fix).
			   Address is unused beyond this in both programs. */
			char *p = line + 5;
			if(*p == '[') {
				char *rb = strchr(p, ']');
				if(!rb) continue;
				*rb = 0;
				if(!strchr(rb+1, ':')) continue;
			} else {
				char *colon = strchr(p, ':');
				if(!colon) continue;
				*colon = 0;
			}
			int local = connect_to(local_ip, local_port);
			if(local < 0) {
				perror("connect local");
				/* Local fail (matches py fix): old C code kept the
				   paired spare socket, stranding the public client
				   that the server had paired with it. Drop the
				   spare, arm a fresh one, and continue. */
				if(next >= 0) close(next);
				next = client_setup_sock(upstream_ip, upstream_port, "sk2", next_nonce);
				continue;
			}
			if(tunnel_add(&threads, &nthreads, &capthreads, local, next, 1, next_nonce) < 0) {
				close(local); close(next);
				continue;
			}
			next = client_setup_sock(upstream_ip, upstream_port, "sk2", next_nonce);
			if(next < 0) break;
		}
	}
}

/* ---- NAT server ---- */

static int server_wait_conn_up(int su, int *control, int *next_up, int *next_enc, char *next_nonce) {
	union sockaddr_union addr;
	socklen_t alen = sizeof addr;
	int conn = accept(su, (struct sockaddr*)&addr, &alen);
	if(conn < 0) return -1;
	/* Handshake timeout (matches py fix): a client that
	   connects and sends nothing must not freeze the server. */
	{
		struct timeval tv;
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}
	char nonce[NONCE_HEX_LEN+1];
	get_nonce(nonce);
	char addrstr[64];
	format_addr(&addr, addrstr, sizeof addrstr);
	print_timestamp();
	printf("CONN: %s (nonce: %s) ... ", addrstr, nonce);
	fflush(stdout);
	char out[NONCE_HEX_LEN+2];
	memcpy(out, nonce, NONCE_HEX_LEN);
	out[NONCE_HEX_LEN] = '\n';
	out[NONCE_HEX_LEN+1] = 0;
	if(send_all(conn, out, NONCE_HEX_LEN+1) < 0) { close(conn); printf("rejected!\n"); return 0; }
	char cmdbuf[HASH_HEX_LEN+2];
	/* python: conn.recv(1+hashlen).rstrip(b'\n') - plain recv, may be short.
	   We read exactly hashlen+1; a short read is a rejected client. */
	if(recv_exact(conn, cmdbuf, HASH_HEX_LEN+1) < 0) { printf("rejected!\n"); close(conn); return 0; }
	{
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}
	cmdbuf[HASH_HEX_LEN+1] = 0;
	size_t cl = HASH_HEX_LEN+1;
	while(cl > 0 && cmdbuf[cl-1] == '\n') { cmdbuf[--cl] = 0; }
	char expect[HASH_HEX_LEN+1];
	compute_hash("adm", nonce, expect);
	if(cl == HASH_HEX_LEN && ct_equal(cmdbuf, expect, HASH_HEX_LEN)) {
		if(*control >= 0) close(*control);
		/* Orphan spare (matches py fix): old code left the
		   spare from the dead admin session in place. */
		if(*next_up >= 0) { close(*next_up); *next_up = -1; }
		*control = conn;
		printf("OK (admin)\n");
	} else {
		compute_hash("skt", nonce, expect);
		int is_skt = cl == HASH_HEX_LEN && ct_equal(cmdbuf, expect, HASH_HEX_LEN);
		compute_hash("sk2", nonce, expect);
		int is_sk2 = cl == HASH_HEX_LEN && ct_equal(cmdbuf, expect, HASH_HEX_LEN);
		if(is_skt || is_sk2) {
			printf("OK (tunnel%s)\n", is_sk2 ? " enc" : "");
			if(*control < 0) close(conn);
			else {
				if(*next_up >= 0) close(*next_up);
				*next_up = conn;
				*next_enc = is_sk2;
				if(next_nonce) strcpy(next_nonce, nonce);
			}
		} else {
			printf("rejected!\n");
			close(conn);
		}
	}
	fflush(stdout);
	return 0;
}

static void server_doit(const char *up_ip, unsigned short up_port, const char *client_ip, unsigned short client_port) {
	int su = listen_on(up_ip, up_port);
	if(su < 0) { perror("listen admin"); return; }
	int sc = listen_on(client_ip, client_port);
	if(sc < 0) { perror("listen public"); return; }
	int control = -1;
	int next_up = -1;
	int next_enc = 0;
	char next_nonce_srv[NONCE_HEX_LEN+1];
	struct tunnel **threads = 0;
	size_t nthreads = 0, capthreads = 0;
	while(1) {
		tunnel_reap(&threads, &nthreads);
		if(control < 0) server_wait_conn_up(su, &control, &next_up, &next_enc, next_nonce_srv);
		if(next_up < 0) server_wait_conn_up(su, &control, &next_up, &next_enc, next_nonce_srv);
		if(control >= 0 && next_up >= 0) {
			struct pollfd fds[3];
			fds[0].fd = sc; fds[0].events = POLLIN; fds[0].revents = 0;
			fds[1].fd = control; fds[1].events = POLLIN; fds[1].revents = 0;
			fds[2].fd = next_up; fds[2].events = POLLIN; fds[2].revents = 0;
			int r = poll(fds, 3, -1);
			if(r < 0) {
				if(errno == EINTR) continue;
				continue;
			}
			/* python checks in order control, next_up, sc and does
			   continue after one loss; replicate exactly. */
			if(fds[1].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)) {
				printf("lost control socket\n");
				fflush(stdout);
				close(control);
				control = -1;
				continue;
			}
			if(fds[2].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)) {
				printf("lost spare upstream socket\n");
				fflush(stdout);
				close(next_up);
				next_up = -1;
				continue;
			}
			if(fds[0].revents & POLLIN) {
				union sockaddr_union addr;
				socklen_t alen = sizeof addr;
				int conn = accept(sc, (struct sockaddr*)&addr, &alen);
				if(conn < 0) continue;
				char addrstr[64];
				format_addr(&addr, addrstr, sizeof addrstr);
				char msg[80];
				/* python: b"CONN:%s\n" % addr  (no space) */
				int mlen = snprintf(msg, sizeof msg, "CONN:%s\n", addrstr);
				if(control < 0 || send_all(control, msg, (size_t)mlen) < 0) {
					close(conn);
					continue;
				}
				if(tunnel_add(&threads, &nthreads, &capthreads, next_up, conn, next_enc, next_nonce_srv) < 0) {
					close(next_up); close(conn);
					next_up = -1;
					continue;
				}
				next_up = -1;
			}
		}
	}
}

static void usage(const char *prog) {
	printf(
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
		"Server (IPv4):\n"
		"    %s --mode server --secret s3cretP4ss --public 0.0.0.0:7000 --admin 0.0.0.0:8000\n"
		"Client (IPv4):\n"
		"    %s --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:8000\n"
		"\n"
		"IPv6 and addresses:\n"
		"IPv4 and IPv6 both work. Use host:port, with brackets for\n"
		"IPv6 literals: [::1]:8080, [2001:db8::1]:7000. A bare IPv6\n"
		"address without brackets is rejected (ambiguous port).\n"
		"Host names prefer IPv4 with IPv6 fallback; an explicit\n"
		"numeric literal always wins for its family. Listen 0.0.0.0\n"
		"means IPv4 all, :: means IPv6 all. Peers are reported as\n"
		"ip:port for IPv4 and [ip]:port for IPv6.\n"
		"\n"
		"Server (IPv6):\n"
		"    %s --mode server --secret s3cretP4ss --public [::]:7000 --admin [::]:8000\n"
		"Client (IPv6 upstream):\n"
		"    %s --mode client --secret s3cretP4ss --local localhost:80 --admin [2001:db8::1]:8000\n",
		prog, prog, prog, prog);
}

static int parse_ip_port(const char *s, char *ip, size_t ip_cap, unsigned short *port) {
	/* CLI form is host:port. IPv6 literals must use brackets:
	   [::1]:8080. A bare v6 address is ambiguous with the port
	   separator, so it is rejected here (getaddrinfo would
	   also reject it). */
	const char *colon;
	size_t n;
	if(s[0] == '[') {
		const char *rb = strchr(s, ']');
		if(!rb || rb[1] != ':') return -1;
		colon = rb + 1;
		n = (size_t)(rb - s - 1);
		if(n == 0 || n >= ip_cap) return -1;
		memcpy(ip, s + 1, n);
		ip[n] = 0;
		colon++;
	} else {
		colon = strrchr(s, ':');
		if(!colon) return -1;
		/* Reject bare v6: more than one colon means the host
		   part was not bracketed. */
		if(strchr(s, ':') != colon) return -1;
		n = (size_t)(colon - s);
		if(n == 0 || n >= ip_cap) return -1;
		memcpy(ip, s, n);
		ip[n] = 0;
		colon++;
	}
	char *end = 0;
	long p = strtol(colon, &end, 10);
	if(!end || *end || p < 0 || p > 65535) return -1;
	*port = (unsigned short)p;
	return 0;
}

int main(int argc, char **argv) {
	if(argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		usage(argv[0]);
		if(argc < 2) return 1;
		/* python prints desc then still runs argparse which errors on -h;
		   we just show help and exit 0 for explicit -h/--help */
		return 0;
	}
	const char *secret = 0;
	const char *mode = 0;
	const char *public_addr = "0.0.0.0:8080";
	const char *local_addr = "localhost:80";
	const char *admin_addr = "0.0.0.0:8081";
	int i;
	for(i=1;i<argc;i++) {
		if(strcmp(argv[i], "--secret") == 0 && i+1 < argc) secret = argv[++i];
		else if(strcmp(argv[i], "--mode") == 0 && i+1 < argc) mode = argv[++i];
		else if(strcmp(argv[i], "--public") == 0 && i+1 < argc) public_addr = argv[++i];
		else if(strcmp(argv[i], "--local") == 0 && i+1 < argc) local_addr = argv[++i];
		else if(strcmp(argv[i], "--admin") == 0 && i+1 < argc) admin_addr = argv[++i];
		else if(strncmp(argv[i], "--secret=", 9) == 0) secret = argv[i]+9;
		else if(strncmp(argv[i], "--mode=", 7) == 0) mode = argv[i]+7;
		else if(strncmp(argv[i], "--public=", 9) == 0) public_addr = argv[i]+9;
		else if(strncmp(argv[i], "--local=", 8) == 0) local_addr = argv[i]+8;
		else if(strncmp(argv[i], "--admin=", 8) == 0) admin_addr = argv[i]+8;
		else {
			fprintf(stderr, "unrecognized argument: %s\n", argv[i]);
			return 1;
		}
	}
	if(!secret || !mode) {
		fprintf(stderr, "--secret and --mode are required\n");
		return 1;
	}
	g_secret = secret;
	g_secret_len = strlen(secret);
	signal(SIGPIPE, SIG_IGN);
	char admin_ip[256];
	unsigned short admin_port;
	if(parse_ip_port(admin_addr, admin_ip, sizeof admin_ip, &admin_port) < 0) {
		fprintf(stderr, "bad --admin address: %s\n", admin_addr);
		return 1;
	}
	if(strcmp(mode, "server") == 0) {
		char client_ip[256];
		unsigned short client_port;
		if(parse_ip_port(public_addr, client_ip, sizeof client_ip, &client_port) < 0) {
			fprintf(stderr, "bad --public address: %s\n", public_addr);
			return 1;
		}
		server_doit(admin_ip, admin_port, client_ip, client_port);
	} else if(strcmp(mode, "client") == 0) {
		char local_ip[256];
		unsigned short local_port;
		if(parse_ip_port(local_addr, local_ip, sizeof local_ip, &local_port) < 0) {
			fprintf(stderr, "bad --local address: %s\n", local_addr);
			return 1;
		}
		client_doit(admin_ip, admin_port, local_ip, local_port);
	} else {
		fprintf(stderr, "bad --mode: %s (server or client)\n", mode);
		return 1;
	}
	return 0;
}
