/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <bytes.h>

#include <sys/sha2.h>

static const uint32_t sha256_rk[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint64_t sha512_rk[] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
	0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
	0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
	0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
	0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
	0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
	0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
	0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
	0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
	0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
	0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void sha256_init(struct sha256_ctx *ctx)
{
	struct sha256 *c = (struct sha256 *)ctx;

	assert(c != NULL);
	assert(sizeof(*ctx) == sizeof(*c));

	c->h[0] = 0x6a09e667;
	c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372;
	c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f;
	c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab;
	c->h[7] = 0x5be0cd19;

	c->nwords = c->nbytes = 0;
}

static uint32_t ror32(uint32_t v, int c)
{
	c &= 31;
	return (v >> c) | (v << (32 - c));
}

static void sha256_block(struct sha256 *c)
{
	int i;
	uint32_t s0, s1, ch, t0, t1;
	uint32_t lh[8];
	static uint32_t w[64];

	for (i = 0; i < SHA256_BLOCK_LEN; i += sizeof(uint32_t))
		w[i >> 2] = htonl(*(uint32_t *)(c->buf + i));

	for (i = 16; i < 64; ++i) {
		s0 = 0;
		s0 ^= ror32(w[i - 15], 7);
		s0 ^= ror32(w[i - 15], 18);
		s0 ^= w[i - 15] >> 3;

		s1 = 0;
		s1 ^= ror32(w[i - 2], 17);
		s1 ^= ror32(w[i - 2], 19);
		s1 ^= w[i - 2] >> 10;

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	memcpy(lh, c->h, sizeof(c->h));
	for (i = 0; i < 64; ++i) {
		s1 = 0;
		s1 ^= ror32(lh[4], 6);
		s1 ^= ror32(lh[4], 11);
		s1 ^= ror32(lh[4], 25);

		ch = 0;
		ch ^= lh[4] & lh[5];
		ch ^= (~lh[4]) & lh[6];
		t0 = lh[7] + s1 + ch + sha256_rk[i] + w[i];

		s0 = 0;
		s0 ^= ror32(lh[0], 2);
		s0 ^= ror32(lh[0], 13);
		s0 ^= ror32(lh[0], 22);

		ch = 0;
		ch ^= lh[0] & lh[1];
		ch ^= lh[0] & lh[2];
		ch ^= lh[1] & lh[2];
		t1 = s0 + ch;

		lh[7] = lh[6];
		lh[6] = lh[5];
		lh[5] = lh[4];
		lh[4] = lh[3] + t0;
		lh[3] = lh[2];
		lh[2] = lh[1];
		lh[1] = lh[0];
		lh[0] = t0 + t1;
	}

	for (i = 0; i < 8; ++i)
		c->h[i] += lh[i];

	/* TODO secure. */
	memset(w, -1, sizeof(w));
}

void sha256_update(struct sha256_ctx *ctx, const void *bytes, int len)
{
	struct sha256 *c = (struct sha256 *)ctx;
	int diff, n, src;
	const char *in;

	assert(c != NULL);
	assert(len >= 0);
	if (len == 0)
		return;
	assert(bytes);

	in = bytes;
	src = 0;
	for (; len;) {
		diff = SHA256_BLOCK_LEN - c->nbytes;
		n = diff < len ? diff : len;
		memcpy(c->buf + c->nbytes, in + src, n);
		c->nbytes += n;
		src += n;
		len -= n;

		if (c->nbytes == SHA256_BLOCK_LEN) {
			c->nbytes = 0;
			++c->nwords;
			/* Overflow. */
			assert(c->nwords != 0);
			sha256_block(c);
		}
	}
}

void sha256_final(struct sha256_ctx *ctx, uint8_t *bytes)
{
	struct sha256 *c = (struct sha256 *)ctx;
	int i, j;
	uint8_t byte;
	uint64_t nbits, k, mask, len;

	assert(c != NULL);
	assert(bytes);

	nbits   = c->nwords;
	nbits <<= 9;
	nbits  += c->nbytes << 3;
	len = htobe64(nbits);
	nbits += 1;	/* Append a single bit 1. */
	nbits += 64;	/* 64 == size of the size of the message. */

	mask = ((uint64_t)1 << 9) - 1;
	k = nbits & mask;
	assert(k);
	k = 512 - k;	/* # of zeroes to append. */

	byte = 0x80;
	if (k) {
		assert(k >= 7);
		sha256_update(ctx, &byte, 1);
		k -= 7;
	}

	byte = 0;
	while (k) {
		sha256_update(ctx, &byte, 1);
		k -= 8;
	}
	sha256_update(ctx, &len, sizeof(len));
	for (i = 0; i < SHA256_DIGEST_LEN; i += 4) {
		j = i >> 2;
		bytes[i + 0] = (c->h[j] >> 24) & 0xff;
		bytes[i + 1] = (c->h[j] >> 16) & 0xff;
		bytes[i + 2] = (c->h[j] >> 8) & 0xff;
		bytes[i + 3] = (c->h[j] >> 0) & 0xff;
	}
	memset(ctx, -1, sizeof(*ctx));
}









void sha512_init(struct sha512_ctx *ctx)
{
	struct sha512 *c = (struct sha512 *)ctx;

	assert(c != NULL);
	assert(sizeof(*ctx) == sizeof(*c));

	c->h[0] = 0x6a09e667f3bcc908;
	c->h[1] = 0xbb67ae8584caa73b;
	c->h[2] = 0x3c6ef372fe94f82b;
	c->h[3] = 0xa54ff53a5f1d36f1;
	c->h[4] = 0x510e527fade682d1;
	c->h[5] = 0x9b05688c2b3e6c1f;
	c->h[6] = 0x1f83d9abfb41bd6b;
	c->h[7] = 0x5be0cd19137e2179;

	c->nwords = c->nbytes = 0;
}

static uint64_t ror64(uint64_t v, int c)
{
	c &= 63;
	return (v >> c) | (v << (64 - c));
}

static void sha512_block(struct sha512 *c)
{
	int i;
	uint64_t s0, s1, ch, t0, t1;
	uint64_t lh[8];
	static uint64_t w[80];

	for (i = 0; i < SHA512_BLOCK_LEN; i += sizeof(uint64_t))
		w[i >> 3] = htobe64(*(uint64_t *)(c->buf + i));

	for (i = 16; i < 80; ++i) {
		s0 = 0;
		s0 ^= ror64(w[i - 15], 1);
		s0 ^= ror64(w[i - 15], 8);
		s0 ^= w[i - 15] >> 7;

		s1 = 0;
		s1 ^= ror64(w[i - 2], 19);
		s1 ^= ror64(w[i - 2], 61);
		s1 ^= w[i - 2] >> 6;

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	memcpy(lh, c->h, sizeof(c->h));
	for (i = 0; i < 80; ++i) {
		s1 = 0;
		s1 ^= ror64(lh[4], 14);
		s1 ^= ror64(lh[4], 18);
		s1 ^= ror64(lh[4], 41);

		ch = 0;
		ch ^= lh[4] & lh[5];
		ch ^= (~lh[4]) & lh[6];
		t0 = lh[7] + s1 + ch + sha512_rk[i] + w[i];

		s0 = 0;
		s0 ^= ror64(lh[0], 28);
		s0 ^= ror64(lh[0], 34);
		s0 ^= ror64(lh[0], 39);

		ch = 0;
		ch ^= lh[0] & lh[1];
		ch ^= lh[0] & lh[2];
		ch ^= lh[1] & lh[2];
		t1 = s0 + ch;

		lh[7] = lh[6];
		lh[6] = lh[5];
		lh[5] = lh[4];
		lh[4] = lh[3] + t0;
		lh[3] = lh[2];
		lh[2] = lh[1];
		lh[1] = lh[0];
		lh[0] = t0 + t1;
	}

	for (i = 0; i < 8; ++i)
		c->h[i] += lh[i];

	/* TODO secure. */
	memset(w, -1, sizeof(w));
}

void sha512_update(struct sha512_ctx *ctx, const void *bytes, int len)
{
	struct sha512 *c = (struct sha512 *)ctx;
	int diff, n, src;
	const char *in;

	assert(c != NULL);
	assert(len >= 0);
	if (len == 0)
		return;
	assert(bytes);

	in = bytes;
	src = 0;
	for (; len;) {
		diff = SHA512_BLOCK_LEN - c->nbytes;
		n = diff < len ? diff : len;
		memcpy(c->buf + c->nbytes, in + src, n);
		c->nbytes += n;
		src += n;
		len -= n;

		if (c->nbytes == SHA512_BLOCK_LEN) {
			c->nbytes = 0;
			++c->nwords;
			/* Overflow. */
			assert(c->nwords != 0);
			sha512_block(c);
		}
	}
}

void sha512_final(struct sha512_ctx *ctx, uint8_t *bytes)
{
	struct sha512 *c = (struct sha512 *)ctx;
	int i, j;
	uint8_t byte;
	uint64_t nbits, k, mask, len;

	assert(c != NULL);
	assert(bytes);

	nbits   = c->nwords;
	nbits <<= 10;
	nbits  += c->nbytes << 3;
	len = htobe64(nbits);
	nbits += 1;	/* Append a single bit 1. */
	nbits += 128;	/* 128 == size of the size of the message. */

	mask = ((uint64_t)1 << 10) - 1;
	k = nbits & mask;
	assert(k);
	k = 1024 - k;	/* # of zeroes to append. */

	byte = 0x80;
	if (k) {
		assert(k >= 7);
		sha512_update(ctx, &byte, 1);
		k -= 7;
	}

	byte = 0;
	while (k) {
		sha512_update(ctx, &byte, 1);
		k -= 8;
	}

	/* We do not support the full 128-bit message length. */
	sha512_update(ctx, &k, sizeof(k));
	sha512_update(ctx, &len, sizeof(len));
	for (i = 0; i < SHA512_DIGEST_LEN; i += 8) {
		j = i >> 3;
		bytes[i + 0] = (c->h[j] >> 56) & 0xff;
		bytes[i + 1] = (c->h[j] >> 48) & 0xff;
		bytes[i + 2] = (c->h[j] >> 40) & 0xff;
		bytes[i + 3] = (c->h[j] >> 32) & 0xff;
		bytes[i + 4] = (c->h[j] >> 24) & 0xff;
		bytes[i + 5] = (c->h[j] >> 16) & 0xff;
		bytes[i + 6] = (c->h[j] >> 8) & 0xff;
		bytes[i + 7] = (c->h[j] >> 0) & 0xff;
	}
	memset(ctx, -1, sizeof(*ctx));
}
