/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <string.h>
#include <endian.h>	/* Non-standard. */

#include <sys/chacha.h>

const char *sigma = "expand 32-byte k";

/* TODO endianness, overflow. */

/*
 * Conforms to RFC 7539, and not the original ChaCha spec.
 * That is, 32 bytes key, 96-bit noce, 32-bit blk counter.
 */
void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key,
		   const void *nonce, uint32_t blk)
{
	struct chacha20 *c = (struct chacha20 *)ctx;
	const uint32_t *cnst = (const uint32_t *)sigma;
	const uint32_t *k = (const uint32_t *)key;
	const uint32_t *n = nonce;

	assert(sizeof(*c) == sizeof(*ctx));
	assert(c);
	assert(key);
	assert(nonce);

	c->state[0]	= htole32(cnst[0]);
	c->state[1]	= htole32(cnst[1]);
	c->state[2]	= htole32(cnst[2]);
	c->state[3]	= htole32(cnst[3]);

	c->state[4]	= htole32(k[0]);
	c->state[5]	= htole32(k[1]);
	c->state[6]	= htole32(k[2]);
	c->state[7]	= htole32(k[3]);
	c->state[8]	= htole32(k[4]);
	c->state[9]	= htole32(k[5]);
	c->state[10]	= htole32(k[6]);
	c->state[11]	= htole32(k[7]);

	c->state[12]	= blk;	/* blk is already numeric. */
	c->state[13]	= htole32(n[0]);
	c->state[14]	= htole32(n[1]);
	c->state[15]	= htole32(n[2]);

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


	for (i = 0; i < 16; ++i) {
		stream[i] += c->state[i];
		stream[i] = le32toh(stream[i]);
	}

	++c->state[12];
	assert(c->state[12]);
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
