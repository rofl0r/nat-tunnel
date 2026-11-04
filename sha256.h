#ifndef SHA256_H
#define SHA256_H
#include <stddef.h>
#include <stdint.h>
#define SHA256_DIGEST_SIZE 32
typedef struct {
	uint32_t h[8];
	uint64_t len;
	unsigned char buf[64];
	size_t buflen;
} sha256_ctx;
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *buf, size_t n);
void sha256_final(sha256_ctx *ctx, unsigned char out[SHA256_DIGEST_SIZE]);
#endif
