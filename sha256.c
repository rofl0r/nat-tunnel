#include "sha256.h"
#include <string.h>
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))
static const uint32_t K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
void sha256_init(sha256_ctx *ctx) {
	ctx->h[0]=0x6a09e667; ctx->h[1]=0xbb67ae85; ctx->h[2]=0x3c6ef372; ctx->h[3]=0xa54ff53a;
	ctx->h[4]=0x510e527f; ctx->h[5]=0x9b05688c; ctx->h[6]=0x1f83d9ab; ctx->h[7]=0x5be0cd19;
	ctx->len=0; ctx->buflen=0;
}
static void block(sha256_ctx *ctx, const unsigned char *p) {
	uint32_t w[64];
	int i;
	for(i=0;i<16;i++) w[i]=((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|(uint32_t)p[4*i+3];
	for(i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
	uint32_t a=ctx->h[0],b=ctx->h[1],c=ctx->h[2],d=ctx->h[3],e=ctx->h[4],f=ctx->h[5],g=ctx->h[6],h=ctx->h[7];
	for(i=0;i<64;i++) {
		uint32_t t1=h+EP1(e)+CH(e,f,g)+K[i]+w[i];
		uint32_t t2=EP0(a)+MAJ(a,b,c);
		h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
	}
	ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
	ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}
void sha256_update(sha256_ctx *ctx, const unsigned char *buf, size_t n) {
	ctx->len += n;
	while(n) {
		size_t take = 64 - ctx->buflen;
		if(take > n) take = n;
		memcpy(ctx->buf + ctx->buflen, buf, take);
		ctx->buflen += take; buf += take; n -= take;
		if(ctx->buflen == 64) { block(ctx, ctx->buf); ctx->buflen = 0; }
	}
}
void sha256_final(sha256_ctx *ctx, unsigned char out[SHA256_DIGEST_SIZE]) {
	uint64_t bits = ctx->len * 8;
	/* Work on a copy so final() is idempotent: the old code
	   fed padding through sha256_update(), which mutated len
	   and buf, so a second final() (or reuse after final())
	   produced a wrong digest. */
	sha256_ctx tmp = *ctx;
	ctx = &tmp;
	unsigned char pad = 0x80;
	sha256_update(ctx, &pad, 1);
	pad = 0;
	while(ctx->buflen != 56) sha256_update(ctx, &pad, 1);
	unsigned char lb[8];
	int i;
	for(i=0;i<8;i++) lb[i] = (unsigned char)(bits >> (56 - 8*i));
	/* feed length manually to avoid len change side effect on pad logic */
	for(i=0;i<8;i++) {
		ctx->buf[ctx->buflen++] = lb[i];
		if(ctx->buflen == 64) { block(ctx, ctx->buf); ctx->buflen = 0; }
	}
	for(i=0;i<8;i++) {
		out[4*i]=(unsigned char)(ctx->h[i]>>24);
		out[4*i+1]=(unsigned char)(ctx->h[i]>>16);
		out[4*i+2]=(unsigned char)(ctx->h[i]>>8);
		out[4*i+3]=(unsigned char)ctx->h[i];
	}
}
