/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <string.h>

#include <sys/chacha.h>

const char *sigma = "expand 32-byte k";
const char *tau = "expand 16-byte k";

/* TODO endianness, overflow. */

void chacha20_init(struct chacha20_ctx *ctx, const void *key, int klen,
		   const void *nonce)
{
	struct chacha20 *c = (struct chacha20 *)ctx;
	const uint32_t *cnst;
	const uint32_t *k = key;
	const uint32_t *n = nonce;

	assert(sizeof(*c) == sizeof(*ctx));
	assert(klen == 32 || klen == 16);
	assert(c);
	assert(key);
	assert(nonce);

	c->state[4] = k[0];
	c->state[5] = k[1];
	c->state[6] = k[2];
	c->state[7] = k[3];
	if (klen == 32) {
		cnst = (const uint32_t *)sigma;
		k += 4;
	} else {
		cnst = (const uint32_t *)tau;
	}
	c->state[8] = k[0];
	c->state[9] = k[1];
	c->state[10] = k[2];
	c->state[11] = k[3];

	c->state[0] = cnst[0];
	c->state[1] = cnst[1];
	c->state[2] = cnst[2];
	c->state[3] = cnst[3];

	c->state[12] = 0;
	c->state[13] = 0;
	c->state[14] = n[0];
	c->state[15] = n[1];

	/* Nothing left in the stream. */
	c->ix = 64;
}

static uint32_t rol32(uint32_t v, int c)
{
	c &= 31;
	return (v << c) | (v >> (32 - c));
}

#define QR(s, a, b, c, d)						\
	do {								\
		s[a] += s[b]; s[d] ^= s[a]; s[d] = rol32(s[d], 16);	\
		s[c] += s[d]; s[b] ^= s[c]; s[b] = rol32(s[b], 12);	\
		s[a] += s[b]; s[d] ^= s[a]; s[d] = rol32(s[d], 8);	\
		s[c] += s[d]; s[b] ^= s[c]; s[b] = rol32(s[b], 7);	\
	} while(0)

static void chacha20_block(struct chacha20 *c)
{
	int i;
	uint32_t *stream;

	stream = c->stream;

	memcpy(stream, c->state, sizeof(c->state));
	for (i = 0; i < 10; ++i) {
		QR(stream, 0, 4, 8, 12);
		QR(stream, 1, 5, 9, 13);
		QR(stream, 2, 6, 10, 14);
		QR(stream, 3, 7, 11, 15);

		QR(stream, 0, 5, 10, 15);
		QR(stream, 1, 6, 11, 12);
		QR(stream, 2, 7, 8, 13);
		QR(stream, 3, 4, 9, 14);
	}

	for (i = 0; i < 16; ++i)
		stream[i] += c->state[i];

	++c->state[12];
	if (c->state[12] == 0)
		++c->state[13];
	assert(c->state[12] || c->state[13]);
}

void chacha20_enc(struct chacha20_ctx *ctx, const void *in, void *out, int len)
{
	int i, left, n;
	const uint8_t *p;
	uint8_t *q, *s;
	struct chacha20 *c;

	assert(ctx);
	c = (struct chacha20 *)ctx;
	p = in;
	q = out;
	s = (uint8_t *)c->stream;

	for (;len;) {
		/* Anything left over in the stream? */
		left = 64 - c->ix;
		n = left < len ? left : len;
		for (i = 0; i < n; ++i)
			q[i] = p[i] ^ s[c->ix + i];
		c->ix += n;
		q += n;
		p += n;
		len -= n;

		if (c->ix == 64) {
			chacha20_block(c);
			c->ix = 0;
		}
	}
}

void chacha20_dec(struct chacha20_ctx *ctx, const void *in, void *out, int len)
{
	chacha20_enc(ctx, in, out, len);
}
