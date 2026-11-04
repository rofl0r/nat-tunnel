#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sha256.h"

#define NONCE_LEN 8
#define NONCE_HEX_LEN (NONCE_LEN*2)
#define HASH_HEX_LEN (SHA256_DIGEST_SIZE*2)
#define BUFSZ 1024

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
	int fd = open("/dev/urandom", 0);
	if(fd >= 0) {
		size_t got = 0;
		while(got < NONCE_LEN) {
			ssize_t r = read(fd, raw+got, NONCE_LEN-got);
			if(r <= 0) break;
			got += (size_t)r;
		}
		close(fd);
		if(got != NONCE_LEN)
			memset(raw, 0, sizeof raw);
	} else {
		srand((unsigned)(time(NULL) ^ (long)getpid()));
		size_t i;
		for(i=0;i<NONCE_LEN;i++) raw[i] = (unsigned char)rand();
	}
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

/* Mimic python resolve(): numeric IPv4 fast path, otherwise first
   AF_UNSPEC SOCK_STREAM result, preferring v4 implicitly via order.
   Python: isnumericipv4 -> v4, else getaddrinfo (AF_UNSPEC, AI_PASSIVE)
   and skip non-v4 if want_v4 (default True). So effectively v4 only
   unless getaddrinfo returns only v6? No: it skips all non-v4, so
   only v4 is ever returned. Keep that: pick first AF_INET. */
static int is_numeric_v4(const char *ip) {
	unsigned int a,b,c,d;
	char extra;
	/* reject trailing junk, empty, and negatives */
	if(sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return 0;
	return a < 256 && b < 256 && c < 256 && d < 256;
}

static int resolve_v4(const char *host, unsigned short port, int passive, struct sockaddr_in *out, socklen_t *outlen) {
	if(is_numeric_v4(host)) {
		memset(out, 0, sizeof *out);
		out->sin_family = AF_INET;
		out->sin_port = htons(port);
		if(inet_pton(AF_INET, host, &out->sin_addr) != 1) return -1;
		if(outlen) *outlen = sizeof *out;
		return 0;
	}
	struct addrinfo *ai = 0;
	if(resolve_host(host, port, passive, &ai)) return -1;
	struct addrinfo *p;
	int rc = -1;
	for(p = ai; p; p = p->ai_next) {
		if(p->ai_family != AF_INET) continue;
		if(p->ai_addrlen != sizeof *out) continue;
		memcpy(out, p->ai_addr, sizeof *out);
		if(outlen) *outlen = sizeof *out;
		rc = 0;
		break;
	}
	freeaddrinfo(ai);
	return rc;
}

static int connect_to(const char *host, unsigned short port) {
	struct sockaddr_in addr;
	socklen_t len;
	if(resolve_v4(host, port, 0, &addr, &len) < 0) return -1;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0) return -1;
	if(connect(fd, (struct sockaddr*)&addr, len) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int listen_on(const char *host, unsigned short port) {
	struct sockaddr_in addr;
	socklen_t len;
	if(resolve_v4(host, port, 1, &addr, &len) < 0) return -1;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0) return -1;
	int yes = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
	if(bind(fd, (struct sockaddr*)&addr, len) < 0) {
		close(fd);
		return -1;
	}
	if(listen(fd, 1) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void format_addr(const struct sockaddr_in *a, char *out, size_t cap) {
	char ip[INET_ADDRSTRLEN];
	const char *s = inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip);
	if(!s) s = "?";
	snprintf(out, cap, "%s:%u", s, (unsigned)ntohs(a->sin_port));
}

struct tunnel {
	int fds;
	int fdc;
	pthread_t pt;
	volatile int done;
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

static int tunnel_start(struct tunnel **slot, int fds, int fdc) {
	struct tunnel *t = malloc(sizeof *t);
	if(!t) return -1;
	t->fds = fds;
	t->fdc = fdc;
	t->done = 0;
	if(pthread_create(&t->pt, 0, tunnel_thread, t) != 0) {
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

static int tunnel_add(struct tunnel ***arr, size_t *count, size_t *cap, int fds, int fdc) {
	if(*count == *cap) {
		size_t ncap = *cap ? *cap * 2 : 8;
		struct tunnel **nt = realloc(*arr, ncap * sizeof *nt);
		if(!nt) return -1;
		*arr = nt;
		*cap = ncap;
	}
	if(tunnel_start(&(*arr)[*count], fds, fdc) != 0) return -1;
	(*count)++;
	return 0;
}

/* ---- NAT client ---- */

static int client_setup_sock(const char *upstream_ip, unsigned short upstream_port, const char *cmd) {
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
	return fd;
}

static void client_doit(const char *upstream_ip, unsigned short upstream_port, const char *local_ip, unsigned short local_port) {
	int control = client_setup_sock(upstream_ip, upstream_port, "adm");
	if(control < 0) return;
	int next = client_setup_sock(upstream_ip, upstream_port, "skt");
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
				control = client_setup_sock(upstream_ip, upstream_port, "adm");
				if(control < 0) continue;
				next = client_setup_sock(upstream_ip, upstream_port, "skt");
				if(next < 0) { close(control); control = -1; }
			}
			continue;
		}
		print_timestamp();
		fputs(line, stdout);
		if(linelen && line[linelen-1] != '\n') fputc('\n', stdout);
		fflush(stdout);
		if(strncmp(line, "CONN:", 5) == 0) {
			/* python: addr = line.rstrip('\n').split(':')[1]
			   note: for IPv6 this would break too; keep same logic for v4.
			   line is "CONN:ip:port\n" -> after first ':' is ip, second ':' port.
			   Actually split(':')[1] gives ip part only in python? Wait:
			   "CONN:1.2.3.4:1234".split(':') -> [CONN, 1.2.3.4, 1234], [1]=ip.
			   But Tunnel addr is unused except stored. So we keep same: parse ip. */
			char *p = line + 5;
			char *colon = strchr(p, ':');
			if(!colon) continue;
			*colon = 0;
			/* addr unused beyond this in python; local_conn ignores it */
			int local = connect_to(local_ip, local_port);
			if(local < 0) {
				perror("connect local");
				/* python would raise; we drop this one tunnel and continue.
				   next_csock must still be consumed/replaced like python does
				   only on success path? In python the exception propagates
				   and program dies. To stay close, we do NOT replace next. */
				continue;
			}
			if(tunnel_add(&threads, &nthreads, &capthreads, local, next) < 0) {
				close(local); close(next);
				continue;
			}
			next = client_setup_sock(upstream_ip, upstream_port, "skt");
			if(next < 0) break;
		}
	}
}

/* ---- NAT server ---- */

static int server_wait_conn_up(int su, int *control, int *next_up) {
	struct sockaddr_in addr;
	socklen_t alen = sizeof addr;
	int conn = accept(su, (struct sockaddr*)&addr, &alen);
	if(conn < 0) return -1;
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
	cmdbuf[HASH_HEX_LEN+1] = 0;
	size_t cl = HASH_HEX_LEN+1;
	while(cl > 0 && cmdbuf[cl-1] == '\n') { cmdbuf[--cl] = 0; }
	char expect[HASH_HEX_LEN+1];
	compute_hash("adm", nonce, expect);
	if(cl == HASH_HEX_LEN && memcmp(cmdbuf, expect, HASH_HEX_LEN) == 0) {
		if(*control >= 0) close(*control);
		*control = conn;
		printf("OK (admin)\n");
	} else {
		compute_hash("skt", nonce, expect);
		if(cl == HASH_HEX_LEN && memcmp(cmdbuf, expect, HASH_HEX_LEN) == 0) {
			printf("OK (tunnel)\n");
			if(*control < 0) close(conn);
			else {
				if(*next_up >= 0) close(*next_up);
				*next_up = conn;
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
	struct tunnel **threads = 0;
	size_t nthreads = 0, capthreads = 0;
	while(1) {
		tunnel_reap(&threads, &nthreads);
		if(control < 0) server_wait_conn_up(su, &control, &next_up);
		if(next_up < 0) server_wait_conn_up(su, &control, &next_up);
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
				struct sockaddr_in addr;
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
				if(tunnel_add(&threads, &nthreads, &capthreads, next_up, conn) < 0) {
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
		"Server:\n"
		"    %s --mode server --secret s3cretP4ss --public 0.0.0.0:7000 --admin 0.0.0.0:8000\n"
		"Client:\n"
		"    %s --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:8000\n",
		prog, prog);
}

static int parse_ip_port(const char *s, char *ip, size_t ip_cap, unsigned short *port) {
	const char *colon = strrchr(s, ':');
	if(!colon) return -1;
	size_t n = (size_t)(colon - s);
	if(n == 0 || n >= ip_cap) return -1;
	memcpy(ip, s, n);
	ip[n] = 0;
	char *end = 0;
	long p = strtol(colon+1, &end, 10);
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
