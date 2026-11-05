#include "sha256.h"
#include <string.h>
#if defined(__SHA__) && defined(__SSSE3__)
#include <immintrin.h>
#define HAVE_SHA_NI 1
#endif
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

#ifdef HAVE_SHA_NI
/* SHA256-NI compression, copied from RHash librhash/sha_ni.c
   (Jeffrey Walton, public domain, based on Intel sample).
   Only the SHA256 block function is used; our update/final
   scaffolding is unchanged. State is ctx->h[8] host order,
   same as RHash unsigned* state. */
static void block_sha_ni(sha256_ctx *ctx, const unsigned char *p)
{
	__m128i STATE0, STATE1;
	__m128i MSG, TMP;
	__m128i MSG0, MSG1, MSG2, MSG3;
	__m128i ABEF_SAVE, CDGH_SAVE;
	__m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
	uint32_t *state = ctx->h;
	TMP = _mm_loadu_si128((const __m128i*) &state[0]);
	STATE1 = _mm_loadu_si128((const __m128i*) &state[4]);
	TMP = _mm_shuffle_epi32(TMP, 0xB1);
	STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
	STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
	STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);
	ABEF_SAVE = STATE0;
	CDGH_SAVE = STATE1;
	MSG = _mm_loadu_si128((const __m128i*) (p+0));
	MSG0 = _mm_shuffle_epi8(MSG, MASK);
	MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG1 = _mm_loadu_si128((const __m128i*) (p+16));
	MSG1 = _mm_shuffle_epi8(MSG1, MASK);
	MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
	MSG2 = _mm_loadu_si128((const __m128i*) (p+32));
	MSG2 = _mm_shuffle_epi8(MSG2, MASK);
	MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
	MSG3 = _mm_loadu_si128((const __m128i*) (p+48));
	MSG3 = _mm_shuffle_epi8(MSG3, MASK);
	MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
	MSG0 = _mm_add_epi32(MSG0, TMP);
	MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
	MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
	MSG1 = _mm_add_epi32(MSG1, TMP);
	MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
	MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
	MSG2 = _mm_add_epi32(MSG2, TMP);
	MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
	MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
	MSG3 = _mm_add_epi32(MSG3, TMP);
	MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
	MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
	MSG0 = _mm_add_epi32(MSG0, TMP);
	MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
	MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
	MSG1 = _mm_add_epi32(MSG1, TMP);
	MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
	MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
	MSG2 = _mm_add_epi32(MSG2, TMP);
	MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
	MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
	MSG3 = _mm_add_epi32(MSG3, TMP);
	MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
	MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
	MSG0 = _mm_add_epi32(MSG0, TMP);
	MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
	MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
	MSG1 = _mm_add_epi32(MSG1, TMP);
	MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
	MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
	MSG2 = _mm_add_epi32(MSG2, TMP);
	MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
	MSG3 = _mm_add_epi32(MSG3, TMP);
	MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
	STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
	STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
	STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
	TMP = _mm_shuffle_epi32(STATE0, 0x1B);
	STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
	STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
	STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);
	_mm_storeu_si128((__m128i*) &state[0], STATE0);
	_mm_storeu_si128((__m128i*) &state[4], STATE1);
}
#endif

static void block(sha256_ctx *ctx, const unsigned char *p) {
#ifdef HAVE_SHA_NI
	block_sha_ni(ctx, p);
	return;
#endif
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
