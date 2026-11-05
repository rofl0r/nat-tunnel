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
#include <netinet/tcp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#include <linux/random.h>
#endif
#include "sha256.h"

#define NONCE_LEN 8
#define NONCE_HEX_LEN (NONCE_LEN*2)
#define HASH_HEX_LEN (SHA256_DIGEST_SIZE*2)
#define BUFSZ (16*1024)
/* Fixed per-thread stack size, ported from microsocks. The
   microsocks ifdeffery (PTHREAD_STACK_MIN, per-OS overrides)
   is dropped: 64KB is enough for the tunnel thread on any
   OS, whose biggest stack user is getaddrinfo in libc. */
#define THREAD_STACK_SIZE (64*1024)

static const char *g_secret;
static size_t g_secret_len;
static char g_secret_buf[4096];
static int g_secret_from_file;
static long g_timeout = 1800; /* seconds, 0 = no timeout */

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
	if(g_timeout > 0) {
		struct timeval tv;
		tv.tv_sec = g_timeout;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}
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

static void print_timestamp(void) {
	time_t t = time(NULL);
	struct tm tmv;
	localtime_r(&t, &tmv);
	char buf[64];
	size_t n = strftime(buf, sizeof buf, "[%Y-%m-%d %H:%M:%S] ", &tmv);
	if(n) fwrite(buf, 1, n, stdout);
	fflush(stdout);
}

/* Single RNG entry point for the whole file. get_nonce() for
   legacy hex nonces and randombytes() for TweetNaCl keypair
   generation both call this. Fail closed, no weak fallback. */
static void rng_fill(unsigned char *buf, size_t n) {
	size_t got = 0;
#ifdef HAVE_GETRANDOM
	while(got < n) {
		ssize_t r = getrandom(buf+got, n-got, 0);
		if(r < 0) { if(errno == EINTR) continue; perror("getrandom"); exit(1); }
		if(r == 0) break;
		got += (size_t)r;
	}
	if(got != n) { fprintf(stderr, "getrandom short read\n"); exit(1); }
#else
	int fd = open("/dev/urandom", 0);
	if(fd < 0) { perror("open /dev/urandom"); exit(1); }
	while(got < n) {
		ssize_t r = read(fd, buf+got, n-got);
		if(r <= 0) { perror("read /dev/urandom"); exit(1); }
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
/* TweetNaCl keypair functions need randombytes(). Implement it
   from /dev/urandom (or getrandom with HAVE_GETRANDOM) so
   crypto_sign_keypair and crypto_scalarmult_base work. */
#include <stdlib.h>
#include <fcntl.h>
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
static int g_have_server_key;
static unsigned char g_pinned_pk[32];
static int g_have_pin;
static int g_allow_cleartext = 1;

static int load_server_key(const char *path) {
	int fd = open(path, 0);
	if(fd < 0) { perror(path); return -1; }
	char pkhex[65];
	unsigned char sk[64];
	ssize_t n = read(fd, pkhex, 64);
	if(n != 64) { fprintf(stderr, "bad key file (need 64 hex pk chars)\n"); return -1; }
	pkhex[64] = 0;
	if(hex_parse(pkhex, g_server_pk, 32) < 0) { fprintf(stderr, "bad pk hex in key file\n"); return -1; }
	/* skip newline if present, then read binary sk or hex sk */
	{
		char c;
		ssize_t r = read(fd, &c, 1);
		if(r == 1 && c != '\n' && c != '\r') {
			/* c is first byte of binary sk */
			sk[0] = (unsigned char)c;
			n = read(fd, sk+1, 63);
			if(n != 63) { fprintf(stderr, "short sk in key file\n"); return -1; }
		} else {
			n = read(fd, sk, 64);
			if(n != 64) { fprintf(stderr, "short sk in key file\n"); return -1; }
		}
	}
	close(fd);
	memcpy(g_server_sk, sk, 64);
	memset(sk, 0, sizeof sk);
	g_have_server_key = 1;
	return 0;
}

static void x25519_base(unsigned char *out, const unsigned char *sk) {
	if(NCRYPT_SCALARMULT_BASE(out, sk) != 0) {
		fprintf(stderr, "crypto_scalarmult_base failed\n");
		exit(1);
	}
}
static void x25519_mul(unsigned char *out, const unsigned char *sk, const unsigned char *pk) {
	if(NCRYPT_SCALARMULT(out, sk, pk) != 0) {
		fprintf(stderr, "crypto_scalarmult failed (bad peer key)\n");
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
		ssize_t n;
		/* Tunnel channel is a raw byte stream: the cipher is
		   continuous across chunks, so no per-chunk framing
		   is needed. One recv plus one send per chunk.
		   Close is signalled by TCP FIN via the half-close
		   shutdown below. Framing is kept only on the
		   control channel (CONN lines need parsing). */
		n = recv(infd, buf, sizeof buf, 0);
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
			if(infd == t->fds) ctr_crypt(&t->enc_up, (unsigned char*)buf, (size_t)n);
			else ctr_crypt(&t->enc_dn, (unsigned char*)buf, (size_t)n);
		}
		{
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
	}
	if(t->fdc >= 0) close(t->fdc);
	if(t->fds >= 0) close(t->fds);
	t->fdc = -1;
	t->fds = -1;
	t->done = 1;
	return 0;
}

static unsigned char g_tun_up[32], g_tun_dn[32], g_tun_n24[32];
static struct ctr_stream g_ctl_up, g_ctl_dn; /* control channel streams */
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
	ctr_init_ex(&g_ctl_up, up, n24);
	ctr_init_ex(&g_ctl_dn, dn, n24);
	g_ctl_valid = 1;
}
static void tun_init_from(const unsigned char *shared, const unsigned char *thash) {
	stream_keys(shared, thash, g_tun_up, g_tun_dn, g_tun_n24);
}
/* ---- NAT client ---- */

static int client_setup_sock(const char *upstream_ip, unsigned short upstream_port, unsigned char req) {
	int fd = connect_to(upstream_ip, upstream_port);
	if(fd < 0) { perror("connect upstream"); return -1; }
	/* recv SERVER_HELLO frame */
	unsigned char ftype;
	unsigned char payload[MAX_FRAME];
	size_t plen = 0;
	if(recv_frame(fd, &ftype, payload, MAX_FRAME, &plen) < 0 || ftype != FT_SH || plen != 117) {
		fprintf(stderr, "bad server hello\n");
		close(fd); return -1;
	}
	const unsigned char *sh_payload = payload;
	if(memcmp(sh_payload, NT_MAGIC, 4) != 0) { fprintf(stderr, "bad magic\n"); close(fd); return -1; }
	const unsigned char *eph_s = sh_payload + 4;
	unsigned char cap = sh_payload[36];
	const unsigned char *nonce = sh_payload + 37;
	const unsigned char *sig = sh_payload + 53;
	/* verify signature over MAGIC+eph_s+cap+nonce (53 bytes) */
	if(ed_verify(sig, sh_payload, 53) != 0) {
		fprintf(stderr, "server signature verify failed\n");
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

static void client_doit(const char *upstream_ip, unsigned short upstream_port, const char *local_ip, unsigned short local_port) {
		int control = client_setup_sock(upstream_ip, upstream_port, 0);
	if(control < 0) return;
	int next = client_setup_sock(upstream_ip, upstream_port, 2);
	if(next < 0) { close(control); return; }
	struct tunnel **threads = 0;
	size_t nthreads = 0, capthreads = 0;
	while(1) {
		tunnel_reap(&threads, &nthreads);
		unsigned char ftype;
		unsigned char line[4096];
		size_t linelen = 0;
		if(recv_frame(control, &ftype, line, sizeof line, &linelen) < 0 || ftype == FT_ERROR || ftype == FT_CLOSE || !g_ctl_valid) {
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
				control = client_setup_sock(upstream_ip, upstream_port, 0);
				if(control < 0) continue;
				next = client_setup_sock(upstream_ip, upstream_port, 2);
				if(next < 0) { close(control); control = -1; }
			}
			continue;
		}
		if(ftype != FT_CTRL) continue;
		ctr_crypt(&g_ctl_dn, line, linelen);
		line[linelen] = 0;
		print_timestamp();
		fputs((char*)line, stdout);
		fputc('\n', stdout);
		fflush(stdout);
		if(strncmp((char*)line, "CONN:", 5) == 0) {
			/* Parse CONN:ip:port or CONN:[v6]:port (matches py fix).
			   Address is unused beyond this in both programs. */
			char *p = (char*)line + 5;
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
				next = client_setup_sock(upstream_ip, upstream_port, 2);
				continue;
			}
			if(!spare_alive(next)) {
				printf("spare socket dead, re-arming\n");
				fflush(stdout);
				close(next);
				next = client_setup_sock(upstream_ip, upstream_port, 2);
				continue;
			}
			if(tunnel_add(&threads, &nthreads, &capthreads, local, next, 1) < 0) {
				close(local); close(next);
				continue;
			}
			next = client_setup_sock(upstream_ip, upstream_port, 2);
			if(next < 0) break;
		}
	}
}

/* ---- NAT server ---- */

static int server_wait_conn_up(int su, int *control, int *next_up, int *next_enc, char *next_nonce) {
	(void)next_nonce;
	union sockaddr_union addr;
	socklen_t alen = sizeof addr;
	int conn = accept(su, (struct sockaddr*)&addr, &alen);
	if(conn < 0) return -1;
	{
		struct timeval tv;
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}
	char addrstr[64];
	format_addr(&addr, addrstr, sizeof addrstr);
	/* SERVER_HELLO: MAGIC + eph_pk + cap + nonce(16) + sig(64) = 117 */
	unsigned char eph_sk[32], eph_pk[32];
	rng_fill(eph_sk, 32);
	x25519_base(eph_pk, eph_sk);
	unsigned char nonce[16];
	rng_fill(nonce, 16);
	unsigned char cap = g_allow_cleartext ? 1 : 0;
	unsigned char sh[117];
	memcpy(sh, NT_MAGIC, 4);
	memcpy(sh+4, eph_pk, 32);
	sh[36] = cap;
	memcpy(sh+37, nonce, 16);
	if(ed_sign(sh+53, sh, 53) != 0) { close(conn); return -1; }
	print_timestamp();
	printf("CONN: %s ... ", addrstr);
	fflush(stdout);
	if(send_frame(conn, FT_SH, sh, 117) < 0) { close(conn); printf("rejected!\n"); return 0; }
	unsigned char ftype;
	unsigned char ch[65];
	size_t plen = 0;
	if(recv_frame(conn, &ftype, ch, 65, &plen) < 0 || ftype != FT_CH || plen != 65) {
		printf("rejected!\n"); close(conn); return 0;
	}
	{
		struct timeval tv;
		tv.tv_sec = 0; tv.tv_usec = 0;
		setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}
	const unsigned char *eph_c = ch;
	unsigned char req = ch[32];
	const unsigned char *mac = ch + 33;
	if(req > 2) { send_error_close(conn, 1); printf("rejected!\n"); close(conn); return 0; }
	unsigned char shared[32], thash[32], expect_mac[32];
	x25519_mul(shared, eph_sk, eph_c);
	transcript_hash(eph_pk, eph_c, cap, nonce, req, thash);
	auth_mac(shared, thash, req, expect_mac);
	if(!ct_equal((char*)mac, (char*)expect_mac, 32)) {
		send_error_close(conn, 3);
		printf("rejected!\n"); close(conn); return 0;
	}
	memset(eph_sk, 0, sizeof eph_sk);
	opt_sock(conn);
	if(req == 0) {
		if(*control >= 0) { close(*control); }
		if(*next_up >= 0) { close(*next_up); *next_up = -1; }
		*control = conn;
		ctl_init_from(shared, thash);
		printf("OK (admin)\n");
	} else {
		int enc = (req == 2);
		if(!enc && !g_allow_cleartext) {
			send_error_close(conn, 1);
			printf("rejected cleartext not allowed\n");
			close(conn); return 0;
		}
		printf("OK (tunnel%s)\n", enc ? " enc" : "");
		if(*control < 0) close(conn);
		else {
			if(*next_up >= 0) close(*next_up);
			*next_up = conn;
			*next_enc = enc;
			tun_init_from(shared, thash);
		}
	}
	memset(shared, 0, sizeof shared);
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
	struct tunnel **threads = 0;
	size_t nthreads = 0, capthreads = 0;
	while(1) {
		tunnel_reap(&threads, &nthreads);
		if(control < 0) server_wait_conn_up(su, &control, &next_up, &next_enc, 0);
		if(next_up < 0) server_wait_conn_up(su, &control, &next_up, &next_enc, 0);
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
				if(!spare_alive(next_up)) {
					printf("lost spare upstream socket\n");
					fflush(stdout);
					close(next_up);
					next_up = -1;
					continue;
				}
				union sockaddr_union addr;
				socklen_t alen = sizeof addr;
				int conn = accept(sc, (struct sockaddr*)&addr, &alen);
				if(conn < 0) continue;
				char addrstr[64];
				format_addr(&addr, addrstr, sizeof addrstr);
				unsigned char msg[80];
				int mlen = snprintf((char*)msg, sizeof msg, "CONN:%s", addrstr);
				if(mlen < 0) mlen = 0;
				if(mlen > (int)sizeof msg) mlen = sizeof msg;
				ctr_crypt(&g_ctl_dn, msg, (size_t)mlen); /* control is server->client only: both ends use dn stream */
				if(control < 0 || send_frame(control, FT_CTRL, msg, (size_t)mlen) < 0) {
					close(conn);
					continue;
				}
				if(tunnel_add(&threads, &nthreads, &capthreads, next_up, conn, next_enc) < 0) {
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
		"    %s --mode client --secret s3cretP4ss --local localhost:80 --admin [2001:db8::1]:8000\n"
		"\n"
		"nt02 wire protocol (binary, length prefixed frames):\n"
		"server signs ephemeral X25519 key with long term Ed25519 key;\n"
		"client verifies against pinned --server-pubkey, replies with\n"
		"ephemeral key plus request byte (0=adm, 1=skt, 2=sk2) plus\n"
		"MAC over transcript keyed by X25519 shared secret plus\n"
		"--secret / --secret-file. CONN lines are always encrypted\n"
		"on the control channel. Server options:\n"
		"  --server-key FILE     long term signing key (see --genkey)\n"
		"  --allow-cleartext     accept skt tunnels (default)\n"
		"  --no-cleartext        reject skt, sk2 only\n"
		"Client options:\n"
		"  --server-pubkey HEX   pinned server public key (required)\n"
		"  --secret-file PATH    read secret from 0600 file, safer\n"
		"                        than --secret on shared boxes\n"
		"  --genkey --out FILE   generate Ed25519 keypair (0600),\n"
		"                        print public key hex for pinning\n"
		"\n"
		"For shared boxes prefer --secret-file PATH (0600 file) over\n"
		"--secret, which leaks via ps aux. Key generation (single\n"
		"option for both roles, role independent):\n"
		"    %s --genkey --out server.key\n"
		"\n"
		"--timeout SECS: tunnel socket send/recv timeout in seconds\n"
		"(0 = no timeout, default 1800). TCP keepalive probes every\n"
		"30s idle (5s interval, 3 probes) on all sockets.\n",
		prog, prog, prog, prog, prog);
}

static int read_secret_file(const char *path) {
	int fd = open(path, 0);
	if(fd < 0) { perror(path); return -1; }
	ssize_t n = read(fd, g_secret_buf, sizeof g_secret_buf - 1);
	close(fd);
	if(n <= 0) { fprintf(stderr, "empty secret file: %s\n", path); return -1; }
	if(n == (ssize_t)(sizeof g_secret_buf - 1)) { fprintf(stderr, "secret file too long: %s\n", path); return -1; }
	g_secret_buf[n] = 0;
	/* strip one trailing newline/CRLF like a text file */
	while(n > 0 && (g_secret_buf[n-1] == '\n' || g_secret_buf[n-1] == '\r')) g_secret_buf[--n] = 0;
	if(n == 0) { fprintf(stderr, "empty secret in file: %s\n", path); return -1; }
	g_secret = g_secret_buf;
	g_secret_len = (size_t)n;
	g_secret_from_file = 1;
	return 0;
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
	if(NCRYPT_SIGN_KEYPAIR(pk, sk) != 0) { fprintf(stderr, "crypto_sign_keypair failed\n"); return 1; }
	int fd = open(outpath, 1|64|512, 0600);
	if(fd < 0) { perror(outpath); return 1; }
	/* file format: hex pk + newline + hex sk + newline, for pinning */
	char buf[200];
	int m = snprintf(buf, sizeof buf, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		pk[0],pk[1],pk[2],pk[3],pk[4],pk[5],pk[6],pk[7],pk[8],pk[9],pk[10],pk[11],pk[12],pk[13],pk[14],pk[15],pk[16],pk[17],pk[18],pk[19],pk[20],pk[21],pk[22],pk[23],pk[24],pk[25],pk[26],pk[27],pk[28],pk[29],pk[30],pk[31]);
	if(m <= 0 || write(fd, buf, (size_t)m) != m) { perror("write key"); return 1; }
	if(write(fd, sk, 64) != 64) { perror("write key"); return 1; }
	if(write(fd, "\n", 1) != 1) { perror("write key"); return 1; }
	close(fd);
	{
		char hexpk[65];
		int i;
		for(i=0;i<32;i++) snprintf(hexpk+2*i, 3, "%02x", pk[i]);
		hexpk[64] = 0;
		printf("public key: %s\n", hexpk);
		printf("private key written to %s (0600)\n", outpath);
		printf("pin the public key on the peer with the matching hex string\n");
	}
	memset(sk, 0, sizeof sk);
	return 0;
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
	/* --genkey is a standalone mode: generate a keypair and exit.
	   Single option for both roles, since Ed25519 generation
	   is role independent. */
	if(argc >= 2 && strcmp(argv[1], "--genkey") == 0) {
		const char *outpath = 0;
		int i;
		for(i=2;i<argc;i++) {
			if(strcmp(argv[i], "--out") == 0 && i+1 < argc) outpath = argv[++i];
			else if(strncmp(argv[i], "--out=", 6) == 0) outpath = argv[i]+6;
			else { fprintf(stderr, "unrecognized argument: %s\n", argv[i]); return 1; }
		}
		if(!outpath) { fprintf(stderr, "--genkey requires --out FILE\n"); return 1; }
		return do_genkey(outpath);
	}
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
	const char *timeout_s = 0;
	const char *secret_file = 0;
	const char *server_key = 0;
	const char *server_pubkey = 0;
	int allow_clear = -1;
	int i;
	for(i=1;i<argc;i++) {
		if(strcmp(argv[i], "--secret") == 0 && i+1 < argc) secret = argv[++i];
		else if(strcmp(argv[i], "--mode") == 0 && i+1 < argc) mode = argv[++i];
		else if(strcmp(argv[i], "--public") == 0 && i+1 < argc) public_addr = argv[++i];
		else if(strcmp(argv[i], "--local") == 0 && i+1 < argc) local_addr = argv[++i];
		else if(strcmp(argv[i], "--admin") == 0 && i+1 < argc) admin_addr = argv[++i];
		else if(strcmp(argv[i], "--timeout") == 0 && i+1 < argc) timeout_s = argv[++i];
		else if(strcmp(argv[i], "--secret-file") == 0 && i+1 < argc) secret_file = argv[++i];
		else if(strcmp(argv[i], "--server-key") == 0 && i+1 < argc) server_key = argv[++i];
		else if(strcmp(argv[i], "--server-pubkey") == 0 && i+1 < argc) server_pubkey = argv[++i];
		else if(strcmp(argv[i], "--allow-cleartext") == 0) allow_clear = 1;
		else if(strcmp(argv[i], "--no-cleartext") == 0) allow_clear = 0;
		else if(strncmp(argv[i], "--secret=", 9) == 0) secret = argv[i]+9;
		else if(strncmp(argv[i], "--mode=", 7) == 0) mode = argv[i]+7;
		else if(strncmp(argv[i], "--public=", 9) == 0) public_addr = argv[i]+9;
		else if(strncmp(argv[i], "--local=", 8) == 0) local_addr = argv[i]+8;
		else if(strncmp(argv[i], "--admin=", 8) == 0) admin_addr = argv[i]+8;
		else if(strncmp(argv[i], "--timeout=", 10) == 0) timeout_s = argv[i]+10;
		else if(strncmp(argv[i], "--secret-file=", 14) == 0) secret_file = argv[i]+14;
		else if(strncmp(argv[i], "--server-key=", 13) == 0) server_key = argv[i]+13;
		else if(strncmp(argv[i], "--server-pubkey=", 16) == 0) server_pubkey = argv[i]+16;
		else {
			fprintf(stderr, "unrecognized argument: %s\n", argv[i]);
			return 1;
		}
	}
	if(secret && secret_file) {
		fprintf(stderr, "--secret and --secret-file are mutually exclusive\n");
		return 1;
	}
	if((!secret && !secret_file) || !mode) {
		fprintf(stderr, "--secret or --secret-file, and --mode, are required\n");
		return 1;
	}
	if(timeout_s) {
		char *end = 0;
		long v = strtol(timeout_s, &end, 10);
		if(!end || *end || end == timeout_s || v < 0) {
			fprintf(stderr, "bad --timeout value: %s\n", timeout_s);
			return 1;
		}
		g_timeout = v;
	}
	if(secret_file) {
		if(read_secret_file(secret_file) < 0) return 1;
	} else {
		g_secret = secret;
		g_secret_len = strlen(secret);
		/* Best effort: zero the argv copy so a later ps dump
		   (after exec race window) sees zeros. Shell history
		   and the exec race window remain; prefer
		   --secret-file on shared boxes. */
		{
			size_t j;
			for(j=0;j<g_secret_len;j++) ((char*)secret)[j] = 0;
		}
	}
	if(allow_clear >= 0) g_allow_cleartext = allow_clear;
	/* Key requirements: server needs signing key; client needs pin. */
	if(strcmp(mode, "server") == 0) {
		if(!server_key) { fprintf(stderr, "server mode requires --server-key FILE (see --genkey)\n"); return 1; }
		if(load_server_key(server_key) < 0) return 1;
	} else if(strcmp(mode, "client") == 0) {
		if(!server_pubkey) { fprintf(stderr, "client mode requires --server-pubkey HEX\n"); return 1; }
		if(hex_parse(server_pubkey, g_pinned_pk, 32) < 0) { fprintf(stderr, "bad --server-pubkey hex\n"); return 1; }
		g_have_pin = 1;
	}
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
