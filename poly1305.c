/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <string.h>

#include <sys/poly1305.h>

/* Coforms to RFC 7539. */

static const char *prime_str = "3fffffffffffffffffffffffffffffffb";
void poly1305_init(struct poly1305_ctx *ctx, const uint8_t *key)
{
	uint8_t r[16];
	uint8_t s[16];
	struct poly1305 *c;

	assert(ctx);
	assert(key);

	assert(sizeof(*c) == sizeof(*ctx));
	c = (struct poly1305 *)ctx;

	memcpy(r, key, 16);
	memcpy(s, key + 16, 16);

	r[3] &= 0xf;
	r[7] &= 0xf;
	r[11] &= 0xf;
	r[15] &= 0xf;

	r[4] &= 0xfc;
	r[8] &= 0xfc;
	r[12] &= 0xfc;

	c->prime = bn_new_from_string_be(prime_str, 16);
	c->r = bn_new_from_bytes_le(r, 16);
	c->s = bn_new_from_bytes_le(s, 16);
	c->acc = bn_new_zero();
	c->ix = 0;
}

static void poly1305_block(struct poly1305 *c, int len)
{
	struct bn *t;

	t = bn_new_from_bytes_le(c->buf, len);
	bn_add(c->acc, t);
	bn_free(t);

	t = bn_new_from_int(1);
	bn_shl(t, len << 3);
	bn_add(c->acc, t);
	bn_free(t);

	bn_mul(c->acc, c->r);
	bn_mod(c->acc, c->prime);
}

void poly1305_update(struct poly1305_ctx *ctx, const void *msg, int mlen)
{
	int n, left;
	const uint8_t *m;
	struct poly1305 *c;

	assert(ctx);
	assert(mlen >= 0);

	c = (struct poly1305 *)ctx;

	m = msg;
	for (;mlen;) {
		left = 16 - c->ix;
		n = left < mlen ? left : mlen;
		memcpy(&c->buf[c->ix], m, n);
		c->ix += n;
		m += n;
		mlen -= n;

		if (c->ix == 16) {
			poly1305_block(c, c->ix);
			c->ix = 0;
		}
	}
}

void poly1305_final(struct poly1305_ctx *ctx, uint8_t *out)
{
	int n;
	uint8_t *o;
	struct poly1305 *c;

	assert(ctx);
	assert(out);
	c = (struct poly1305 *)ctx;

	if (c->ix)
		poly1305_block(c, c->ix);

	bn_add(c->acc, c->s);
	o = bn_to_bytes_le(c->acc, &n);

	bn_free(c->acc);
	bn_free(c->r);
	bn_free(c->s);
	bn_free(c->prime);

	n = n < 16 ? n : 16;
	memcpy(out, o, n);
	if (n < 16)
		memset(out + n, 0, 16 - n);
}
