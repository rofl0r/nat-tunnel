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
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif
#include "sha256.h"

#define BUFSZ (16*1024)
/* Fixed per-thread stack size, ported from microsocks. The
   microsocks ifdeffery (PTHREAD_STACK_MIN, per-OS overrides)
   is dropped: 64KB is enough for the tunnel thread on any
   OS, whose biggest stack user is getaddrinfo in libc. */
#define THREAD_STACK_SIZE (64*1024)

/* Ported from microsocks sockssrv.c. We log to stderr because
   it is not line buffered: line buffering means malloc, and
   malloc needs a lock in a multithreaded program. dprintf()
   writes directly to the fd, so it needs no stdio lock either
   and is safe from any thread. Every line therefore needs no
   fflush(). Keep printing to the main thread where possible,
   so the output stays well ordered. */
#define dolog(...) dprintf(2, __VA_ARGS__)

static const char *g_secret;
static size_t g_secret_len;
static char g_secret_buf[4096];
static long g_timeout = 1800; /* seconds, 0 = no timeout */

/* Set or clear SO_SNDTIMEO/SO_RCVTIMEO. secs 0 clears the
   timeout, i.e. an infinite wait. */
static void sock_timeout(int fd, int secs, int send, int recv_) {
	struct timeval tv;
	tv.tv_sec = secs;
	tv.tv_usec = 0;
	if(send) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	if(recv_) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

/* Keepalive only (30s idle, 5s interval, 3 probes). Never set
   the tunnel recv/send timeout on the control socket: its
   recv_line must block indefinitely while idle. */
static void opt_sock(int fd) {
	int yes = 1;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof yes);
	int idle = 30, intvl = 5, cnt = 3;
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
}

static void tunnel_sock(int fd) {
	opt_sock(fd);
	if(g_timeout > 0) sock_timeout(fd, (int)g_timeout, 1, 1);
}

/* Zero timeout poll: dead iff ERR/HUP/NVAL, or POLLIN with a
   zero-length peek (FIN). Plain POLLIN with data is NOT death:
   the server pairs the spare before sending CONN, so tunnel
   data can legitimately be in flight when this runs. */
static int spare_alive(int fd) {
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	int r;
	do { r = poll(&pfd, 1, 0); } while(r < 0 && errno == EINTR);
	if(r <= 0) return 1;
	if(pfd.revents & (POLLERR|POLLHUP|POLLNVAL)) return 0;
	if(pfd.revents & POLLIN) {
		char c;
		ssize_t n = recv(fd, &c, 1, MSG_PEEK|MSG_DONTWAIT);
		if(n == 0) return 0;
	}
	return 1;
}

static int recv_frame(int fd, unsigned char *type, unsigned char *payload, size_t cap, size_t *out_len);
/* Wait up to timeout_ms for a readable first byte, then read one
   frame. Returns 0 on a frame, -1 on end of socket, -2 on timeout,
   -3 on an over-long frame. The control socket must never use
   SO_RCVTIMEO, so this poll is the only idle wait on it. */
static int wait_frame(int fd, int timeout_ms, unsigned char *type, unsigned char *payload, size_t cap, size_t *out_len) {
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	int r;
	do { r = poll(&pfd, 1, timeout_ms); } while(r < 0 && errno == EINTR);
	if(r == 0) return -2;
	if(r < 0) return -1;
	if(pfd.revents & (POLLERR|POLLHUP|POLLNVAL)) {
		/* Hangup: data may still be buffered, read it first. */
		if(!(pfd.revents & POLLIN)) return -1;
	}
	return recv_frame(fd, type, payload, cap, out_len);
}

/* Kill a socket dead without flushing: RST on the wire, so the peer
   drops it at once instead of after a timeout. Used for sockets
   that must never become the control or the spare socket. */
static void kill_sock(int fd) {
	struct linger lg;
	lg.l_onoff = 1;
	lg.l_linger = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
	close(fd);
}

/* Timestamp prefix in a caller supplied buffer, for dolog().
   A prefix and its message must go out in one dprintf() call,
   so no other thread can interleave a line between them. */
static const char *ts_prefix(char *buf, size_t cap) {
	time_t t = time(NULL);
	struct tm tmv;
	localtime_r(&t, &tmv);
	if(strftime(buf, cap, "[%Y-%m-%d %H:%M:%S] ", &tmv) == 0) buf[0] = 0;
	return buf;
}

/* Single RNG entry point for the whole file. get_nonce() for
   legacy hex nonces and randombytes() for TweetNaCl keypair
   generation both call this. Fail closed, no weak fallback. */
static void rng_fill(unsigned char *buf, size_t n) {
	size_t got = 0;
#ifdef HAVE_GETRANDOM
	while(got < n) {
		ssize_t r = getrandom(buf+got, n-got, 0);
		if(r < 0) { if(errno == EINTR) continue; dolog("getrandom: %s\n", strerror(errno)); exit(1); }
		if(r == 0) break;
		got += (size_t)r;
	}
	if(got != n) { dolog("getrandom short read\n"); exit(1); }
#else
	int fd = open("/dev/urandom", 0);
	if(fd < 0) { dolog("open /dev/urandom: %s\n", strerror(errno)); exit(1); }
	while(got < n) {
		ssize_t r = read(fd, buf+got, n-got);
		if(r <= 0) { dolog("read /dev/urandom: %s\n", strerror(errno)); exit(1); }
		got += (size_t)r;
	}
	close(fd);
#endif
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

/* sk2 stream cipher: XSalsa20, per tunnel, per direction.
   Default backend is TweetNaCl (tweetnacl.c, public domain),
   streaming via crypto_core_* with a persistent 64-bit block
   counter. With USE_SODIUM=1 it links libsodium instead and
   uses crypto_stream_xsalsa20_xor_ic with a persistent block
   counter. Key: sha256(label + secret + nonce), label
   "enc-up" or "enc-dn" (32 bytes). Nonce24 is derived as
   sha256("enc-nonce" + secret + nonce) truncated to 24
   bytes. Directions never share a key stream. */
#ifdef USE_SODIUM
#include <sodium.h>
#define NCRYPT_SCALARMULT_BASE crypto_scalarmult_base
#define NCRYPT_SCALARMULT crypto_scalarmult
#define NCRYPT_SIGN crypto_sign
#define NCRYPT_SIGN_OPEN crypto_sign_open
#define NCRYPT_SIGN_KEYPAIR crypto_sign_keypair
#else
#include "tweetnacl.h"
#define NCRYPT_SCALARMULT_BASE crypto_scalarmult_curve25519_tweet_base
#define NCRYPT_SCALARMULT crypto_scalarmult_curve25519_tweet
#define NCRYPT_SIGN crypto_sign_ed25519_tweet
#define NCRYPT_SIGN_OPEN crypto_sign_ed25519_tweet_open
#define NCRYPT_SIGN_KEYPAIR crypto_sign_ed25519_tweet_keypair
#define NCRYPT_CORE_SALSA crypto_core_salsa20_tweet
#define NCRYPT_CORE_HSALSA crypto_core_hsalsa20_tweet
#endif
#ifndef USE_SODIUM
void randombytes(unsigned char *x, unsigned long long n) {
	rng_fill(x, (size_t)n);
}
#endif
struct ctr_stream {
	unsigned char key[32];
	unsigned char nonce[24];
	unsigned char subkey[32];
	unsigned long long block_counter;
	unsigned char leftover[64];
	size_t leftover_len;
};

#ifndef USE_SODIUM
static const unsigned char g_sigma[16] = "expand 32-byte k";
static void salsa_block(struct ctr_stream *st) {
	unsigned char z[16];
	int i;
	memcpy(z, st->nonce + 16, 8);
	for(i=0;i<8;i++) z[8+i] = (unsigned char)(st->block_counter >> (8*i));
	NCRYPT_CORE_SALSA(st->leftover, z, st->subkey, g_sigma);
}
#endif
static void ctr_init_ex(struct ctr_stream *st, const unsigned char *key, const unsigned char *nonce24) {
	memcpy(st->key, key, 32);
	memcpy(st->nonce, nonce24, 24);
#ifndef USE_SODIUM
	NCRYPT_CORE_HSALSA(st->subkey, st->nonce, st->key, g_sigma);
#endif
	st->block_counter = 0;
	st->leftover_len = 0;
}
static void ctr_crypt(struct ctr_stream *st, unsigned char *data, size_t n) {
	size_t pos = 0;
	while(pos < n) {
		if(st->leftover_len == 0) {
#ifdef USE_SODIUM
			{
				unsigned char zeros[64];
				memset(zeros, 0, 64);
				crypto_stream_xsalsa20_xor_ic(st->leftover, zeros, 64, st->nonce, st->block_counter, st->key);
			}
#else
			salsa_block(st);
#endif
			st->leftover_len = 64;
			st->block_counter++;
		}
		{
			size_t take = n - pos;
			size_t i;
			if(take > st->leftover_len) take = st->leftover_len;
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

/* ---- nt02 binary framing ----
   Frame: [type:1][len:2 BE][payload len]. Max payload 65535.
   Types: 1=SERVER_HELLO 2=CLIENT_HELLO 3=CONTROL 4=TUNNEL
          5=ERROR 6=CLOSE. Tunnel frames carry <=16384 app bytes. */
#define FT_SH 1
#define FT_CH 2
#define FT_CTRL 3
#define FT_TUNNEL 4
#define FT_ERROR 5
#define FT_CLOSE 6
/* Client loop tick: re-check the spare socket, so a spare that
   died does not wait for a CONN that can never arrive. */
#define SPARE_TICK_MS 5000
#define NT_MAGIC "NT02"
#define MAX_FRAME 65535

static int send_frame(int fd, unsigned char type, const void *payload, size_t len) {
	unsigned char hdr[3];
	hdr[0] = type;
	hdr[1] = (unsigned char)(len >> 8);
	hdr[2] = (unsigned char)(len & 0xff);
	if(send_all(fd, hdr, 3) < 0) return -1;
	if(len && send_all(fd, payload, len) < 0) return -1;
	return 0;
}

static int recv_frame(int fd, unsigned char *type, unsigned char *payload, size_t cap, size_t *out_len) {
	unsigned char hdr[3];
	if(recv_exact(fd, hdr, 3) < 0) return -1;
	*type = hdr[0];
	size_t len = ((size_t)hdr[1] << 8) | hdr[2];
	if(len > cap) return -1;
	if(len && recv_exact(fd, payload, len) < 0) return -1;
	if(out_len) *out_len = len;
	return 0;
}

static void send_error_close(int fd, unsigned char code) {
	unsigned char payload[2];
	payload[0] = code;
	send_frame(fd, FT_ERROR, payload, 1);
}

/* ---- key material ----
   Server longterm Ed25519: pk 32, sk 64 (tweet format: seed+pk).
   Client pins server pk hex. Ephemeral X25519 per connection. */
static int hex_parse(const char *hex, unsigned char *out, size_t outlen);
static unsigned char g_server_pk[32];
static unsigned char g_server_sk[64];
static unsigned char g_pinned_pk[32];
static int g_allow_cleartext = 0; /* encrypted by default */

/* Key file: 64 hex pk chars, then an optional newline, then the
   sk (128 hex chars in the current format, or 64 raw bytes in the
   legacy format). The whole file is read first, so every error
   path closes the fd. */
static int load_server_key(const char *path) {
	char buf[256], hexpk[65];
	unsigned char sk[64];
	ssize_t n, left;
	const char *p;
	char hexsk[129];
	int fd = open(path, 0);
	if(fd < 0) { dolog("%s: %s\n", path, strerror(errno)); return -1; }
	n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if(n < 64) { dolog("short key file: %s\n", path); return -1; }
	buf[n] = 0;
	memcpy(hexpk, buf, 64);
	hexpk[64] = 0;
	if(hex_parse(hexpk, g_server_pk, 32) < 0) { dolog("bad pk hex in key file\n"); return -1; }
	p = buf + 64;
	left = n - 64;
	while(left > 0 && (*p == '\n' || *p == '\r')) { p++; left--; }
	if(left < 64) { dolog("short sk in key file\n"); return -1; }
	if(left >= 128) {
		memcpy(hexsk, p, 128);
		hexsk[128] = 0;
	}
	if(left >= 128 && hex_parse(hexsk, sk, 64) == 0) {
		/* current format: hex sk */
	} else {
		/* legacy format: raw sk */
		memcpy(sk, p, 64);
	}
	memcpy(g_server_sk, sk, 64);
	memset(sk, 0, sizeof sk);
	return 0;
}

static void x25519_base(unsigned char *out, const unsigned char *sk) {
	if(NCRYPT_SCALARMULT_BASE(out, sk) != 0) {
		dolog("crypto_scalarmult_base failed\n");
		exit(1);
	}
}
static void x25519_mul(unsigned char *out, const unsigned char *sk, const unsigned char *pk) {
	if(NCRYPT_SCALARMULT(out, sk, pk) != 0) {
		dolog("crypto_scalarmult failed (bad peer key)\n");
		exit(1);
	}
}
static unsigned char g_sign_buf[128];
static int ed_sign(unsigned char *sig, const unsigned char *msg, size_t len) {
	unsigned long long slen = 0;
	int r = NCRYPT_SIGN(g_sign_buf, &slen, msg, len, g_server_sk);
	if(r) return r;
	memcpy(sig, g_sign_buf, 64);
	return 0;
}
static int ed_verify(const unsigned char *sig, const unsigned char *msg, size_t len) {
	/* TweetNaCl open expects m to be writable (it copies sm into
	   m in place). Sodium's open accepts m=NULL. Allocate real
	   buffer for both. */
	unsigned char sm[192];
	unsigned char outmsg[192];
	unsigned long long mlen = 0;
	int r;
	memcpy(sm, sig, 64);
	memcpy(sm + 64, msg, len);
	r = NCRYPT_SIGN_OPEN(outmsg, &mlen, sm, 64 + len, g_pinned_pk);
	return r;
}

/* transcript = MAGIC(4) + eph_s(32) + eph_c(32) + cap(1) + nonce(16) + req(1) = 86 */
static void transcript_hash(const unsigned char *eph_s, const unsigned char *eph_c, unsigned char cap, const unsigned char *nonce, unsigned char req, unsigned char out[32]) {
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char*)NT_MAGIC, 4);
	sha256_update(&ctx, eph_s, 32);
	sha256_update(&ctx, eph_c, 32);
	sha256_update(&ctx, &cap, 1);
	sha256_update(&ctx, nonce, 16);
	sha256_update(&ctx, &req, 1);
	sha256_final(&ctx, out);
}
static void auth_mac(const unsigned char *shared, const unsigned char *thash, unsigned char req, unsigned char out[32]) {
	unsigned char auth_key[32];
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char*)"auth", 4);
	sha256_update(&ctx, shared, 32);
	sha256_update(&ctx, (const unsigned char*)g_secret, g_secret_len);
	sha256_final(&ctx, auth_key);
	sha256_init(&ctx);
	sha256_update(&ctx, auth_key, 32);
	sha256_update(&ctx, thash, 32);
	sha256_update(&ctx, &req, 1);
	sha256_final(&ctx, out);
	memset(auth_key, 0, sizeof auth_key);
}
/* stream keys from shared + transcript (forward secret) */
static void stream_keys(const unsigned char *shared, const unsigned char *thash, unsigned char up[32], unsigned char dn[32], unsigned char n24[32]) {
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char*)"enc-up", 6);
	sha256_update(&ctx, shared, 32);
	sha256_update(&ctx, thash, 32);
	sha256_final(&ctx, up);
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char*)"enc-dn", 6);
	sha256_update(&ctx, shared, 32);
	sha256_update(&ctx, thash, 32);
	sha256_final(&ctx, dn);
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char*)"enc-nonce", 9);
	sha256_update(&ctx, shared, 32);
	sha256_update(&ctx, thash, 32);
	sha256_final(&ctx, n24);
}

/* resolve host like microsocks/server.c resolve(), but without AI_PASSIVE
   for client connections and with it for listen sockets. */
static int resolve_host(const char *host, unsigned short port, int passive, struct addrinfo **out) {
	struct addrinfo hints;
	char port_buf[8];
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if(passive) hints.ai_flags = AI_PASSIVE;
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

/* Address of a known family first, then the first address of the
   other family, so a dead v4 never blocks a live v6. */
static void addr_order(struct addrinfo *ai, struct addrinfo *order[2]) {
	order[0] = pick_best(ai);
	order[1] = 0;
	if(order[0]) {
		struct addrinfo *p;
		for(p = ai; p; p = p->ai_next)
			if(p != order[0] && !order[1]) order[1] = p;
	}
}

static int connect_to(const char *host, unsigned short port) {
	/* Unix socket path for --local: host is a pathname starting
	   with '/'. Port is ignored. Lets microsocks (also unix)
	   chain without any open TCP ports on the natted box. */
	if(host[0] == '/') {
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if(fd < 0) return -1;
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof addr);
		addr.sun_family = AF_UNIX;
		if(strlen(host) >= sizeof addr.sun_path) { close(fd); return -1; }
		strcpy(addr.sun_path, host);
		if(connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) { close(fd); return -1; }
		return fd;
	}
	struct addrinfo *ai = 0;
	if(resolve_host(host, port, 0, &ai) < 0) return -1;
	struct addrinfo *order[2];
	addr_order(ai, order);
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
	if(resolve_host(host, port, 1, &ai) < 0) return -1;
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
/* Move one bufferful from in to out, encrypting with st when it is
   set. Returns 1 when bytes moved, 0 when retried after EINTR, -1
   on EOF or error, so the caller can half close that direction.
   The cipher is a continuous stream, so chunks need no framing. */
static int tunnel_pump(int infd, int outfd, struct ctr_stream *st) {
	char buf[BUFSZ];
	ssize_t n = recv(infd, buf, sizeof buf, 0);
	if(n < 0) {
		if(errno == EINTR) return 0;
		return -1;
	}
	if(n == 0) return -1;
	if(st) ctr_crypt(st, (unsigned char*)buf, (size_t)n);
	return send_all(outfd, buf, (size_t)n) == 0 ? 1 : -1;
}

static void *tunnel_thread(void *data) {
	struct tunnel *t = data;
	int open0 = 1, open1 = 1;
	struct pollfd fds[2];
	while(open0 || open1) {
		int r, in, out, rc;
		struct ctr_stream *st;
		fds[0].fd = open0 ? t->fds : -1;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = open1 ? t->fdc : -1;
		fds[1].events = POLLIN;
		fds[1].revents = 0;
		r = poll(fds, 2, -1);
		if(r < 0) {
			if(errno == EINTR) continue;
			break;
		}
		/* Pick the readable side. An error or hangup without POLLIN
		   means that side is done, so half close the other way. */
		if(fds[0].revents) {
			in = t->fds; out = t->fdc;
			st = t->enc ? &t->enc_up : 0;
			rc = (fds[0].revents & POLLIN) ? tunnel_pump(in, out, st) : -1;
			if(rc < 0) { open0 = 0; shutdown(out, SHUT_WR); }
			if(rc > 0 || rc < 0) continue;
		}
		if(fds[1].revents) {
			in = t->fdc; out = t->fds;
			st = t->enc ? &t->enc_dn : 0;
			rc = (fds[1].revents & POLLIN) ? tunnel_pump(in, out, st) : -1;
			if(rc < 0) { open1 = 0; shutdown(out, SHUT_WR); }
			if(rc > 0 || rc < 0) continue;
		}
	}
	if(t->fdc >= 0) close(t->fdc);
	if(t->fds >= 0) close(t->fds);
	t->fdc = -1;
	t->fds = -1;
	t->done = 1;
	return 0;
}

static unsigned char g_tun_up[32], g_tun_dn[32], g_tun_n24[32];
static struct ctr_stream g_ctl_dn; /* control channel, server to client */
static int g_ctl_valid;
static int tunnel_start(struct tunnel **slot, int fds, int fdc, int enc) {
	struct tunnel *t = malloc(sizeof *t);
	if(!t) return -1;
	t->fds = fds;
	t->fdc = fdc;
	t->done = 0;
	t->enc = enc;
	tunnel_sock(fds);
	tunnel_sock(fdc);
	if(enc) {
		ctr_init_ex(&t->enc_up, g_tun_up, g_tun_n24);
		ctr_init_ex(&t->enc_dn, g_tun_dn, g_tun_n24);
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

static int tunnel_add(struct tunnel ***arr, size_t *count, size_t *cap, int fds, int fdc, int enc) {
	if(*count == *cap) {
		size_t ncap = *cap ? *cap * 2 : 8;
		struct tunnel **nt = realloc(*arr, ncap * sizeof *nt);
		if(!nt) return -1;
		*arr = nt;
		*cap = ncap;
	}
	if(tunnel_start(&(*arr)[*count], fds, fdc, enc) != 0) return -1;
	(*count)++;
	return 0;
}

static void ctl_init_from(const unsigned char *shared, const unsigned char *thash) {
	unsigned char up[32], dn[32], n24[32];
	stream_keys(shared, thash, up, dn, n24);
	/* The control channel is server to client only, so the up
	   stream is never used. */
	ctr_init_ex(&g_ctl_dn, dn, n24);
	g_ctl_valid = 1;
}
static void tun_init_from(const unsigned char *shared, const unsigned char *thash) {
	stream_keys(shared, thash, g_tun_up, g_tun_dn, g_tun_n24);
}
/* ---- NAT client ---- */

static int client_setup_sock(const char *upstream_ip, unsigned short upstream_port, unsigned char req) {
	int fd = connect_to(upstream_ip, upstream_port);
	if(fd < 0) { dolog("connect upstream: %s\n", strerror(errno)); return -1; }
	/* recv SERVER_HELLO frame */
	unsigned char ftype;
	unsigned char payload[MAX_FRAME];
	size_t plen = 0;
	if(recv_frame(fd, &ftype, payload, MAX_FRAME, &plen) < 0 || ftype != FT_SH || plen != 117) {
		dolog("bad server hello\n");
		close(fd); return -1;
	}
	const unsigned char *sh_payload = payload;
	if(memcmp(sh_payload, NT_MAGIC, 4) != 0) { dolog("bad magic\n"); close(fd); return -1; }
	const unsigned char *eph_s = sh_payload + 4;
	unsigned char cap = sh_payload[36];
	const unsigned char *nonce = sh_payload + 37;
	const unsigned char *sig = sh_payload + 53;
	/* verify signature over MAGIC+eph_s+cap+nonce (53 bytes) */
	if(ed_verify(sig, sh_payload, 53) != 0) {
		dolog("server signature verify failed\n");
		send_error_close(fd, 2);
		close(fd); return -1;
	}
	/* our ephemeral */
	unsigned char eph_sk[32], eph_c[32];
	rng_fill(eph_sk, 32);
	x25519_base(eph_c, eph_sk);
	unsigned char shared[32], thash[32], mac[32];
	x25519_mul(shared, eph_sk, eph_s);
	transcript_hash(eph_s, eph_c, cap, nonce, req, thash);
	auth_mac(shared, thash, req, mac);
	unsigned char ch_payload[65];
	memcpy(ch_payload, eph_c, 32);
	ch_payload[32] = req;
	memcpy(ch_payload + 33, mac, 32);
	if(send_frame(fd, FT_CH, ch_payload, 65) < 0) { close(fd); return -1; }
	/* keys */
	if(req == 0) {
		ctl_init_from(shared, thash);
	} else {
		tun_init_from(shared, thash);
	}
	memset(eph_sk, 0, sizeof eph_sk);
	memset(shared, 0, sizeof shared);
	opt_sock(fd);
	return fd;
}

/* The client keeps exactly one armed spare socket: a raw tunnel
   socket that the server pairs with the next public connection.
   Only the server writes to a spare, and only after pairing. */
struct spare {
	const char *ip;
	unsigned short port;
	int fd;
};

/* Drop the spare. RST it, so the server sees it gone at once and
   does not pair it with a public connection that then hangs. */
static void spare_drop(struct spare *sp) {
	if(sp->fd >= 0) kill_sock(sp->fd);
	sp->fd = -1;
}

/* Hand the spare to a tunnel thread. The thread owns the fd now. */
static void spare_release(struct spare *sp) {
	sp->fd = -1;
}

/* Arm a fresh spare, dropping the old one first. Returns -1 when
   the upstream cannot be reached. */
static int spare_arm(struct spare *sp, char *tsbuf, size_t tslen) {
	const char *why = 0;
	if(sp->fd >= 0) { spare_drop(sp); why = "dead"; }
	sp->fd = client_setup_sock(sp->ip, sp->port, 2);
	if(sp->fd < 0) return -1;
	if(why) dolog("%sspare socket dead, re-arming\n", ts_prefix(tsbuf, tslen));
	return 0;
}

/* Handshake control and spare. Retry every 2s until both are up.
   An attempt starts at once, so a restart recovers fast and a
   lost server only costs the poll interval. */
static void client_reconnect(int *control, struct spare *sp) {
	*control = -1;
	sp->fd = -1;
	while(*control < 0) {
		*control = client_setup_sock(sp->ip, sp->port, 0);
		if(*control < 0) goto retry;
		if(spare_arm(sp, 0, 0) == 0) return;
		close(*control);
		*control = -1;
retry:
		{
			struct timespec ts;
			ts.tv_sec = 2;
			ts.tv_nsec = 0;
			nanosleep(&ts, 0);
		}
	}
}

/* Read and act on one control frame. Returns -1 when the control
   socket is gone. */
static int client_ctrl_frame(int control, struct spare *sp, const char *local_ip, unsigned short local_port,
                             struct tunnel ***threads, size_t *nthreads, size_t *capthreads, char *tsbuf, size_t tslen) {
	unsigned char ftype;
	unsigned char line[4096];
	size_t linelen = 0;
	if(recv_frame(control, &ftype, line, sizeof line, &linelen) < 0 || ftype == FT_ERROR || ftype == FT_CLOSE || !g_ctl_valid) return -1;
	if(ftype != FT_CTRL) return 0;
	ctr_crypt(&g_ctl_dn, line, linelen);
	line[linelen] = 0;
	dolog("%s%s\n", ts_prefix(tsbuf, tslen), (char*)line);
	if(strncmp((char*)line, "CONN:", 5) != 0) return 0;
	{
		/* Parse CONN:ip:port or CONN:[v6]:port. The address is
		   unused beyond the parse in both programs. */
		char *cp = (char*)line + 5;
		if(*cp == '[') {
			char *rb = strchr(cp, ']');
			if(!rb) return 0;
			*rb = 0;
			if(!strchr(rb+1, ':')) return 0;
		} else {
			char *colon = strchr(cp, ':');
			if(!colon) return 0;
			*colon = 0;
		}
	}
	/* A dead spare must never be paired: the public peer would
	   hang on a tunnel that never opens. */
	if(sp->fd < 0 || !spare_alive(sp->fd)) {
		if(spare_arm(sp, tsbuf, tslen) < 0) return -1;
		return 0;
	}
	{
		int local = connect_to(local_ip, local_port);
		if(local < 0) {
			dolog("%sconnect local: %s\n", ts_prefix(tsbuf, tslen), strerror(errno));
			if(spare_arm(sp, tsbuf, tslen) < 0) return -1;
			return 0;
		}
		if(tunnel_add(threads, nthreads, capthreads, local, sp->fd, 1) < 0) {
			close(local);
			if(spare_arm(sp, tsbuf, tslen) < 0) return -1;
			return 0;
		}
		spare_release(sp);
	}
	if(spare_arm(sp, tsbuf, tslen) < 0) return -1;
	return 0;
}

static void client_doit(const char *upstream_ip, unsigned short upstream_port, const char *local_ip, unsigned short local_port) {
	int control = -1;
	struct spare sp;
	char tsbuf[64];
	struct tunnel **threads = 0;
	size_t nthreads = 0, capthreads = 0;
	sp.ip = upstream_ip;
	sp.port = upstream_port;
	sp.fd = -1;
	client_reconnect(&control, &sp);
	while(1) {
		struct pollfd fds[2];
		int r;
		tunnel_reap(&threads, &nthreads);
		/* The spare is armed before every wait, so a dead spare
		   never blocks the client and never holds up a server
		   that is waiting for one. */
		if(sp.fd < 0 && spare_arm(&sp, tsbuf, sizeof tsbuf) < 0) goto lost_control;
		fds[0].fd = control; fds[0].events = POLLIN; fds[0].revents = 0;
		fds[1].fd = sp.fd; fds[1].events = POLLIN; fds[1].revents = 0;
		do { r = poll(fds, 2, SPARE_TICK_MS); } while(r < 0 && errno == EINTR);
		if(r < 0) goto lost_control;
		if(r == 0) {
			/* Tick: replace a spare that died silently, e.g.
			   dropped NAT state. Waiting for a CONN would
			   deadlock, since the server sends none while it
			   has no spare. */
			if(!spare_alive(sp.fd) && spare_arm(&sp, tsbuf, sizeof tsbuf) < 0) goto lost_control;
			continue;
		}
		/* Readable is not death: the server pairs the spare before
		   it writes CONN, so tunnel bytes can be queued here
		   already. Only a zero length peek means FIN. */
		if(fds[1].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)) {
			if(fds[1].revents & (POLLERR|POLLHUP|POLLNVAL) || !spare_alive(sp.fd)) {
				if(spare_arm(&sp, tsbuf, sizeof tsbuf) < 0) goto lost_control;
				continue;
			}
		}
		if(fds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) goto lost_control;
		if(!(fds[0].revents & POLLIN)) continue;
		if(client_ctrl_frame(control, &sp, local_ip, local_port, &threads, &nthreads, &capthreads, tsbuf, sizeof tsbuf) < 0) goto lost_control;
		continue;
lost_control:
		/* Lost control: tear down control and spare, then
		   re-handshake with backoff. Tunnels stay up. */
		dolog("%slost control socket, reconnecting\n", ts_prefix(tsbuf, sizeof tsbuf));
		if(control >= 0) close(control);
		spare_drop(&sp);
		client_reconnect(&control, &sp);
	}
}

/* ---- NAT server ---- */

/* Handshake deadline for an accepted peer, in milliseconds. A
   real NT client answers SERVER_HELLO at once, so this only
   bounds the wait for a port scanner that connects and stalls. */
#define HELLO_WAIT_MS 1500

/* The server keeps one control socket and one armed spare. The
   public listener pairs the spare with each accepted peer. */
struct server {
	int su;          /* admin listener */
	int sc;          /* public listener */
	int control;     /* control socket, -1 when none */
	int spare;       /* armed spare socket, -1 when none */
	int spare_enc;   /* spare is an encrypted tunnel socket */
	struct tunnel **threads;
	size_t nthreads;
	size_t capthreads;
	char tsbuf[64];
};

static void serve_drop_spare(struct server *sv) {
	if(sv->spare >= 0) kill_sock(sv->spare);
	sv->spare = -1;
}

static void serve_drop_control(struct server *sv) {
	if(sv->control >= 0) close(sv->control);
	sv->control = -1;
}

/* Run the handshake on an already accepted socket. The caller
   sorts out port scanners: a peer that is not the NT client
   fails the MAC check and leaves the control socket untouched.
   Only a peer that holds the shared secret can replace a live
   control socket. */
static void server_handshake(struct server *sv, int conn) {
	union sockaddr_union addr;
	socklen_t alen = sizeof addr;
	char addrstr[64] = "?";
	/* One line per handshake outcome: the timestamp and the result
	   go out in one dprintf(), so concurrent handshakes never
	   interleave inside a line. */
	char log_prefix[64];
	unsigned char eph_sk[32], eph_pk[32], nonce[16];
	unsigned char sh[117];
	unsigned char ftype, ch[65];
	unsigned char req;
	unsigned char shared[32], thash[32], expect_mac[32];
	size_t plen = 0;
	int enc;

	if(getpeername(conn, (struct sockaddr*)&addr, &alen) == 0) format_addr(&addr, addrstr, sizeof addrstr);
	ts_prefix(log_prefix, sizeof log_prefix);
	/* A peer that never reads must not block the handshake. */
	sock_timeout(conn, 5, 1, 0);
	rng_fill(eph_sk, 32);
	x25519_base(eph_pk, eph_sk);
	rng_fill(nonce, 16);
	memcpy(sh, NT_MAGIC, 4);
	memcpy(sh+4, eph_pk, 32);
	sh[36] = g_allow_cleartext ? 1 : 0;
	memcpy(sh+37, nonce, 16);
	if(ed_sign(sh+53, sh, 53) != 0) goto reject;
	if(send_frame(conn, FT_SH, sh, 117) < 0) goto reject;
	/* The only blocking read: a peer that never sends a client
	   hello is killed after HELLO_WAIT_MS. */
	if(wait_frame(conn, HELLO_WAIT_MS, &ftype, ch, 65, &plen) != 0 || ftype != FT_CH || plen != 65) goto reject;
	req = ch[32];
	if(req > 2) goto reject;
	x25519_mul(shared, eph_sk, ch);
	transcript_hash(eph_pk, ch, sh[36], nonce, req, thash);
	auth_mac(shared, thash, req, expect_mac);
	if(!ct_equal((char*)ch + 33, (char*)expect_mac, 32)) goto reject;
	memset(eph_sk, 0, sizeof eph_sk);
	opt_sock(conn);
	sock_timeout(conn, 0, 1, 0);   /* keepalive is on now */
	if(req == 0) {
		/* Reaching here means the peer holds the shared secret, so
		   a takeover of a live control socket is the real client
		   restarting. A port scanner cannot get here. */
		if(sv->control >= 0) { dolog("%scontrol takeover\n", log_prefix); serve_drop_control(sv); }
		serve_drop_spare(sv);
		sv->control = conn;
		ctl_init_from(shared, thash);
		dolog("%sCONN: %s ... OK (admin)\n", log_prefix, addrstr);
		memset(shared, 0, sizeof shared);
		return;
	}
	enc = (req == 2);
	if(!enc && !g_allow_cleartext) {
		dolog("%sCONN: %s ... rejected cleartext not allowed\n", log_prefix, addrstr);
		goto reject;
	}
	dolog("%sCONN: %s ... OK (tunnel%s)\n", log_prefix, addrstr, enc ? " enc" : "");
	serve_drop_spare(sv);
	sv->spare = conn;
	sv->spare_enc = enc;
	tun_init_from(shared, thash);
	memset(shared, 0, sizeof shared);
	return;
reject:
	dolog("%sCONN: %s ... rejected!\n", log_prefix, addrstr);
	kill_sock(conn);
}

/* Take one admin peer through the handshake. A dead spare is
   dropped first, so it can never be paired later. */
static void serve_admin(struct server *sv) {
	union sockaddr_union addr;
	socklen_t alen = sizeof addr;
	int conn = accept(sv->su, (struct sockaddr*)&addr, &alen);
	if(conn < 0) return;
	if(sv->spare >= 0 && !spare_alive(sv->spare)) serve_drop_spare(sv);
	server_handshake(sv, conn);
}

/* Pair the armed spare with one public connection and hand both to
   a tunnel thread. Without a live spare the public peer is reset at
   once, so it never hangs on a tunnel that cannot open. */
static void serve_public(struct server *sv) {
	union sockaddr_union addr;
	socklen_t alen = sizeof addr;
	char addrstr[64];
	char *s = sv->tsbuf;
	int conn = accept(sv->sc, (struct sockaddr*)&addr, &alen);
	if(conn < 0) return;
	format_addr(&addr, addrstr, sizeof addrstr);
	if(sv->spare < 0 || !spare_alive(sv->spare)) {
		serve_drop_spare(sv);
		dolog("%sCONN: %s refused, no spare\n", ts_prefix(s, sizeof sv->tsbuf), addrstr);
		kill_sock(conn);
		return;
	}
	{
		unsigned char msg[80];
		int mlen = snprintf((char*)msg, sizeof msg, "CONN:%s", addrstr);
		if(mlen < 0 || mlen >= (int)sizeof msg) mlen = 0;
		/* Control traffic is server to client only, so both ends
		   use the dn stream. */
		ctr_crypt(&g_ctl_dn, msg, (size_t)mlen);
		if(send_frame(sv->control, FT_CTRL, msg, (size_t)mlen) < 0) {
			dolog("%slost control socket\n", ts_prefix(s, sizeof sv->tsbuf));
			serve_drop_control(sv);
			serve_drop_spare(sv);
			kill_sock(conn);
			return;
		}
	}
	if(tunnel_add(&sv->threads, &sv->nthreads, &sv->capthreads, sv->spare, conn, sv->spare_enc) < 0) {
		serve_drop_spare(sv);
		kill_sock(conn);
		return;
	}
	sv->spare = -1;
}

static void server_doit(const char *up_ip, unsigned short up_port, const char *client_ip, unsigned short client_port) {
	struct server sv;
	memset(&sv, 0, sizeof sv);
	sv.su = listen_on(up_ip, up_port);
	if(sv.su < 0) { dolog("listen admin: %s\n", strerror(errno)); return; }
	sv.sc = listen_on(client_ip, client_port);
	if(sv.sc < 0) { dolog("listen public: %s\n", strerror(errno)); return; }
	sv.control = -1;
	sv.spare = -1;
	while(1) {
		struct pollfd fds[4];
		int r;
		char *s = sv.tsbuf;
		tunnel_reap(&sv.threads, &sv.nthreads);
		/* One poll over everything. No blocking accept, so the
		   public port, the admin port and the control socket
		   stay live while a spare is missing. */
		fds[0].fd = sv.su; fds[0].events = POLLIN; fds[0].revents = 0;
		fds[1].fd = sv.sc; fds[1].events = POLLIN; fds[1].revents = 0;
		fds[2].fd = sv.control; fds[2].events = POLLIN; fds[2].revents = 0;
		fds[3].fd = sv.spare; fds[3].events = POLLIN; fds[3].revents = 0;
		do { r = poll(fds, 4, -1); } while(r < 0 && errno == EINTR);
		if(r < 0) continue;
		/* Order matters. A dead control or spare is handled first,
		   so a peer that arrives at the same moment never
		   replaces a live control socket. */
		if(fds[2].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)) {
			dolog("%slost control socket\n", ts_prefix(s, sizeof sv.tsbuf));
			serve_drop_control(&sv);
			continue;
		}
		if(fds[3].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)) {
			dolog("%slost spare upstream socket\n", ts_prefix(s, sizeof sv.tsbuf));
			serve_drop_spare(&sv);
			continue;
		}
		if(fds[0].revents & POLLIN) { serve_admin(&sv); continue; }
		if(fds[1].revents & POLLIN) { serve_public(&sv); continue; }
	}
}

/* Help text goes to stdout: it is the answer to a CLI call,
   not a log line. All runtime output uses dolog(). */
static void usage(const char *prog) {
	printf(
		"usage: %s [options]\n"
		"  --mode server|client     work mode (required)\n"
		"  --secret SECRET          shared secret (or --secret-file)\n"
		"  --secret-file PATH     read secret from 0600 file\n"
		"  --timeout SECS         tunnel socket timeout, default 1800, 0=none\n"
		"  --help, -h             show this help\n"
		"Server only:\n"
		"  --public HOST:PORT     public listen address (required)\n"
		"  --admin HOST:PORT      admin listen address (required)\n"
		"  --server-key FILE      long term signing key (required, see --genkey)\n"
		"  --allow-cleartext      allow unencrypted tunnel traffic.\n"
		"                         By default tunnels are encrypted.\n"
		"                         This can improve throughput, or\n"
		"                         reduce overhead if the backend is\n"
		"                         already encrypted, e.g. HTTPS.\n"
		"                         Applies only to tunnel traffic,\n"
		"                         control traffic stays encrypted.\n"
		"Client only:\n"
		"  --admin HOST:PORT      server admin address\n"
		"  --local HOST:PORT      local service address (or unix path /path.sock)\n"
		"  --server-pubkey HEX    pinned server public key (required)\n"
		"Key generation (single option, role independent):\n"
		"  %s --genkey FILE       generate Ed25519 keypair to FILE (0600),\n"
		"                           print public key hex for pinning\n"
		"Addresses: host:port, IPv6 as [::1]:8080, unix path as /tmp/x.sock\n"
		"Keepalive: TCP probes every 30s idle (5s interval, 3 probes).\n",
		prog, prog);
}
static int read_secret_file(const char *path) {
	int fd = open(path, 0);
	if(fd < 0) { dolog("%s: %s\n", path, strerror(errno)); return -1; }
	ssize_t n = read(fd, g_secret_buf, sizeof g_secret_buf - 1);
	close(fd);
	if(n <= 0) { dolog("empty secret file: %s\n", path); return -1; }
	if(n == (ssize_t)(sizeof g_secret_buf - 1)) { dolog("secret file too long: %s\n", path); return -1; }
	g_secret_buf[n] = 0;
	/* strip one trailing newline/CRLF like a text file */
	while(n > 0 && (g_secret_buf[n-1] == '\n' || g_secret_buf[n-1] == '\r')) g_secret_buf[--n] = 0;
	if(n == 0) { dolog("empty secret in file: %s\n", path); return -1; }
	g_secret = g_secret_buf;
	g_secret_len = (size_t)n;
	return 0;
}

/* Lower case hex into out. out needs 2*len+1 bytes. */
static void hex_write(char *out, const unsigned char *in, size_t len) {
	size_t i;
	for(i=0;i<len;i++) snprintf(out + 2*i, 3, "%02x", in[i]);
	out[2*len] = 0;
}

static int hex_parse(const char *hex, unsigned char *out, size_t outlen) {
	size_t i;
	if(strlen(hex) != outlen * 2) return -1;
	for(i=0;i<outlen;i++) {
		unsigned int v;
		if(sscanf(hex + 2*i, "%2x", &v) != 1) return -1;
		out[i] = (unsigned char)v;
	}
	return 0;
}

static int do_genkey(const char *outpath) {
	unsigned char pk[32], sk[64];
	char hexpk[65], hexsk[129], buf[200];
	int fd, m, rc = 1;
	if(NCRYPT_SIGN_KEYPAIR(pk, sk) != 0) { dolog("crypto_sign_keypair failed\n"); return 1; }
	hex_write(hexpk, pk, sizeof pk);
	hex_write(hexsk, sk, sizeof sk);
	fd = open(outpath, 1|64|512, 0600);
	if(fd < 0) { dolog("%s: %s\n", outpath, strerror(errno)); goto out; }
	/* file format: hex pk + newline + hex sk + newline, for pinning */
	m = snprintf(buf, sizeof buf, "%s\n%s\n", hexpk, hexsk);
	if(m <= 0 || write(fd, buf, (size_t)m) != m) {
		dolog("write key: %s\n", strerror(errno));
		close(fd);
		goto out;
	}
	if(close(fd) < 0) { dolog("write key: %s\n", strerror(errno)); goto out; }
	dolog("public key: %s\n", hexpk);
	dolog("private key written to %s (0600)\n", outpath);
	dolog("pin the public key on the peer with the matching hex string\n");
	rc = 0;
out:
	memset(sk, 0, sizeof sk);
	return rc;
}

static int parse_ip_port(const char *s, char *ip, size_t ip_cap, unsigned short *port) {
	/* CLI form is host:port. IPv6 literals must use brackets:
	   [::1]:8080. A bare v6 address is ambiguous with the port
	   separator, so it is rejected here (getaddrinfo would
	   also reject it). */
	const char *colon;
	size_t n;
	if(s[0] == '/') {
		/* Unix socket path: no port; whole string is the path. */
		if(strlen(s) >= ip_cap) return -1;
		strcpy(ip, s);
		*port = 0;
		return 0;
	}
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

/* One parsed command line. Text options are strdup()ed, so argv[]
   can be cleared later for --silent-argv. */
struct options {
	char *mode;
	char *secret;
	char *public_addr;
	char *local_addr;
	char *admin_addr;
	char *timeout_s;
	char *secret_file;
	char *server_key;
	char *server_pubkey;
	int allow_clear;
	int silent_argv;
};

/* Match "--name VALUE" and "--name=VALUE" in one place. Returns 1
   and stores the value when argv[i] is that option, else 0. */
static int opt_find(char **argv, int argc, int *i, const char *name, char **slot) {
	size_t n = strlen(name);
	if(strcmp(argv[*i], name) == 0 && *i + 1 < argc) {
		*slot = strdup(argv[++(*i)]);
		return 1;
	}
	if(strncmp(argv[*i], name, n) == 0 && argv[*i][n] == '=') {
		*slot = strdup(argv[*i] + n + 1);
		return 1;
	}
	return 0;
}

/* Split a CLI address into ip and port. Unix socket paths start
   with '/' and carry no port. */
static int opt_addr(const char *text, const char *what, char *ip, size_t ip_cap, unsigned short *port) {
	if(parse_ip_port(text, ip, ip_cap, port) < 0) {
		dolog("bad --%s address: %s\n", what, text);
		return -1;
	}
	return 0;
}

/* Clear argv[] for stealth (ps aux). The kernel already exposed
   the strings at exec time, so this only helps against later
   inspection. Options were strdup()ed during parsing. */
static void hide_argv(int argc, char **argv) {
	int i;
	for(i=1;i<argc;i++) memset(argv[i], 0, strlen(argv[i]));
	/* ./natsrv -> natsrv, so ps shows a bare name. Clear both tail
	   bytes, so no leftover char leaks into the next entry. */
	if(argv[0][0] == '.' && argv[0][1] == '/') {
		size_t n = strlen(argv[0]) - 2;
		memmove(argv[0], argv[0] + 2, n);
		argv[0][n] = 0;
		argv[0][n+1] = 0;
	}
}

int main(int argc, char **argv) {
	struct options o;
	int i;
	/* --genkey FILENAME is a standalone mode: generate a keypair
	   and exit. Single option for both roles. */
	if(argc >= 2 && strcmp(argv[1], "--genkey") == 0) {
		if(argc != 3) { dolog("--genkey requires exactly one filename: --genkey FILENAME\n"); return 1; }
		return do_genkey(argv[2]);
	}
	if(argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		usage(argv[0]);
		return argc < 2 ? 1 : 0;
	}
	memset(&o, 0, sizeof o);
	o.allow_clear = -1;
	for(i=1;i<argc;i++) {
		if(opt_find(argv, argc, &i, "--mode", &o.mode)) continue;
		if(opt_find(argv, argc, &i, "--secret", &o.secret)) continue;
		if(opt_find(argv, argc, &i, "--public", &o.public_addr)) continue;
		if(opt_find(argv, argc, &i, "--local", &o.local_addr)) continue;
		if(opt_find(argv, argc, &i, "--admin", &o.admin_addr)) continue;
		if(opt_find(argv, argc, &i, "--timeout", &o.timeout_s)) continue;
		if(opt_find(argv, argc, &i, "--secret-file", &o.secret_file)) continue;
		if(opt_find(argv, argc, &i, "--server-key", &o.server_key)) continue;
		if(opt_find(argv, argc, &i, "--server-pubkey", &o.server_pubkey)) continue;
		if(strcmp(argv[i], "--silent-argv") == 0) { o.silent_argv = 1; continue; }
		if(strcmp(argv[i], "--allow-cleartext") == 0) { o.allow_clear = 1; continue; }
		dolog("unrecognized argument: %s\n", argv[i]);
		return 1;
	}
	if(o.secret && o.secret_file) { dolog("--secret and --secret-file are mutually exclusive\n"); return 1; }
	if(!o.mode) { dolog("--mode is required (server or client)\n"); return 1; }
	if(!o.secret && !o.secret_file) { dolog("--secret or --secret-file is required\n"); return 1; }
	if(!o.admin_addr) { dolog("--admin is required\n"); return 1; }
	if(strcmp(o.mode, "server") == 0 && !o.public_addr) { dolog("--public is required in server mode\n"); return 1; }
	if(strcmp(o.mode, "client") == 0 && !o.local_addr) { dolog("--local is required in client mode\n"); return 1; }
	if(o.timeout_s) {
		char *end = 0;
		long v = strtol(o.timeout_s, &end, 10);
		if(!end || *end || end == o.timeout_s || v < 0) {
			dolog("bad --timeout value: %s\n", o.timeout_s);
			return 1;
		}
		g_timeout = v;
	}
	if(o.secret_file) {
		if(read_secret_file(o.secret_file) < 0) return 1;
	} else {
		/* The strdup() copy lives for the process lifetime. Shell
		   history and the exec race window remain for --secret;
		   prefer --secret-file. */
		g_secret = o.secret;
		g_secret_len = strlen(o.secret);
	}
	if(o.silent_argv) hide_argv(argc, argv);
	if(o.allow_clear >= 0) g_allow_cleartext = o.allow_clear;
	signal(SIGPIPE, SIG_IGN);
	if(strcmp(o.mode, "server") == 0) {
		char admin_ip[256], public_ip[256];
		unsigned short admin_port, public_port;
		if(!o.server_key) { dolog("server mode requires --server-key FILE (see --genkey)\n"); return 1; }
		if(load_server_key(o.server_key) < 0) return 1;
		if(opt_addr(o.admin_addr, "admin", admin_ip, sizeof admin_ip, &admin_port) < 0) return 1;
		if(opt_addr(o.public_addr, "public", public_ip, sizeof public_ip, &public_port) < 0) return 1;
		server_doit(admin_ip, admin_port, public_ip, public_port);
		return 0;
	}
	if(strcmp(o.mode, "client") == 0) {
		char admin_ip[256], local_ip[256];
		unsigned short admin_port, local_port;
		if(!o.server_pubkey) { dolog("client mode requires --server-pubkey HEX\n"); return 1; }
		if(hex_parse(o.server_pubkey, g_pinned_pk, 32) < 0) { dolog("bad --server-pubkey hex\n"); return 1; }
			if(opt_addr(o.admin_addr, "admin", admin_ip, sizeof admin_ip, &admin_port) < 0) return 1;
		if(opt_addr(o.local_addr, "local", local_ip, sizeof local_ip, &local_port) < 0) return 1;
		client_doit(admin_ip, admin_port, local_ip, local_port);
		return 0;
	}
	dolog("bad --mode: %s (server or client)\n", o.mode);
	return 1;
}
