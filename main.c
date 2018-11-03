/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>

#include <bn.h>
#include <rndm.h>
#include <ec.h>
#include <tls.h>
#include <sha2.h>
#include <hmac.h>
#include <hkdf.h>
#include <chacha.h>
#include <poly1305.h>
#include <aead.h>

/* Numbers as big-endian strings. */
static const char *c25519_prime	=
"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed";
static const char *c25519_a		= "76d06";	// hex(486662)
static const char *c25519_b		= "1";
static const char *c25519_gx		= "9";
static const char *c25519_order	=
"1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed";

struct endpoint {
	struct ec *ec;
	struct bn *espriv, *erpriv, *lspriv, *lrpriv;
	struct ec_point *espub, *lspub, *erpub, *lrpub;
	struct bn *ee[2], *el[2], *le[2];

	uint8_t ak2[32], ek2[32], ak3[32], ek3[32];
	uint8_t tag2[16], tag3[16];
};

struct bn *bn_rand()
{
	int nbits, nbytes;
	uint8_t *bytes;
	struct bn *t;

	nbits = 255;
	nbytes = (nbits + 7) >> 3;
	bytes = malloc(nbytes);
	assert(bytes);
	rndm_fill(bytes, nbits);
	bytes[nbytes - 1] &= 0xf8;
	bytes[0] |= 0x40;
	t = bn_new_from_bytes_be(bytes, nbytes);
	return t;
}

void free_endpoint(struct endpoint *e)
{
	bn_free(e->espriv);
	bn_free(e->lspriv);
	ec_point_free(e->ec, e->espub);
	ec_point_free(e->ec, e->lspub);

	bn_free(e->erpriv);
	bn_free(e->lrpriv);
	ec_point_free(e->ec, e->erpub);
	ec_point_free(e->ec, e->lrpub);

	bn_free(e->ee[0]);
	bn_free(e->ee[1]);
	bn_free(e->el[0]);
	bn_free(e->el[1]);
	bn_free(e->le[0]);
	bn_free(e->le[1]);

	ec_free(e->ec);
}

void init_endpoint(struct endpoint *e)
{
	struct ec_mont_params emp;
	struct ec *ec;

	emp.prime	= c25519_prime;
	emp.a		= c25519_a;
	emp.b		= c25519_b;
	emp.gx		= c25519_gx;
	emp.order	= c25519_order;
	ec = ec_new_montgomery(&emp);

	e->espriv = bn_rand();
	e->lspriv = bn_rand();
	e->espub = ec_gen_public(ec, e->espriv);
	e->lspub = ec_gen_public(ec, e->lspriv);

	e->erpriv = bn_rand();
	e->lrpriv = bn_rand();
	e->erpub = ec_gen_public(ec, e->erpriv);
	e->lrpub = ec_gen_public(ec, e->lrpriv);
	e->ec = ec;
}

struct bn *X25519(const struct ec *ec, const struct bn *priv,
		  const struct ec_point *pub)
{
	struct ec_point *tpub;
	struct bn *x;

	tpub = ec_point_new_copy(ec, pub);
	ec_scale(ec, tpub, priv);
	x = ec_point_x(ec, tpub);
	ec_point_free(ec, tpub);
	return x;
}

const uint8_t zeroes[64];
void shared_secret(struct endpoint *e)
{
	uint8_t *p[8];
	int i, n;
	struct bn *t;
	static uint8_t nonce[16];
	static uint8_t k[3][32];
	static struct chacha20_ctx ctx;
	static struct poly1305_ctx pctx;

	/* Shared secrets. */

	/* X25519(es, ER) == X25519(er, ES). */
	e->ee[0] = X25519(e->ec, e->espriv, e->erpub);
	e->ee[1] = X25519(e->ec, e->erpriv, e->espub);
	assert(bn_cmp_abs(e->ee[0], e->ee[1]) == 0);

	/* X25519(es, LR) == X25519(lr, ES). */
	e->el[0] = X25519(e->ec, e->espriv, e->lrpub);
	e->el[1] = X25519(e->ec, e->lrpriv, e->espub);
	assert(bn_cmp_abs(e->el[0], e->el[1]) == 0);

	/* X25519(ls, ER) == X25519(er, LS). */
	e->le[0] = X25519(e->ec, e->lspriv, e->erpub);
	e->le[1] = X25519(e->ec, e->erpriv, e->lspub);
	assert(bn_cmp_abs(e->le[0], e->le[1]) == 0);

	/* Keys k1, k2, k3 == k[0], k[1], k[2]. */
	memset(nonce, 0, sizeof(nonce));
	p[0] = bn_to_bytes_le(e->ee[0], &n);
	assert(n == 32);
	p[1] = bn_to_bytes_le(e->el[0], &n);
	assert(n == 32);
	p[2] = bn_to_bytes_le(e->le[0], &n);
	assert(n == 32);
	for (i = 0; i < 3; ++i) {
		nonce[0] = i;
		hchacha20(k[i], p[i], nonce);
		free(p[i]);
	}

	for (i = 0; i < 32; ++i)
		k[1][i] ^= k[0][i];

	for (i = 0; i < 32; ++i)
		k[2][i] ^= k[1][i];

	/* AK, EK. */
	chacha20_init(&ctx, k[1], zeroes, 0);
	chacha20_enc(&ctx, e->ak2, zeroes, 32);
	chacha20_enc(&ctx, e->ek2, zeroes, 32);
	chacha20_init(&ctx, k[2], zeroes, 0);
	chacha20_enc(&ctx, e->ak3, zeroes, 32);
	chacha20_enc(&ctx, e->ek3, zeroes, 32);

	/* LS */
	t = ec_point_x(e->ec, e->lspub);
	p[0] = bn_to_bytes_le(t, &n);
	bn_free(t);
	assert(n == 32);

	/* ES */
	t = ec_point_x(e->ec, e->espub);
	p[1] = bn_to_bytes_le(t, &n);
	bn_free(t);
	assert(n == 32);

	/* ER */
	t = ec_point_x(e->ec, e->erpub);
	p[2] = bn_to_bytes_le(t, &n);
	bn_free(t);
	assert(n == 32);

	/* XS */
	t = ec_point_x(e->ec, e->lspub);
	p[3] = bn_to_bytes_le(t, &n);
	bn_free(t);
	assert(n == 32);
	for (i = 0; i < 32; ++i)
		p[3][i] ^= e->ek2[i];

	/* Poly1305(AK2, LS || ES || ER). */
	poly1305_init(&pctx, e->ak2);
	poly1305_update(&pctx, p[0], 32);
	poly1305_update(&pctx, p[1], 32);
	poly1305_update(&pctx, p[2], 32);
	poly1305_final(&pctx, e->tag2);

	/* Poly1305(AK3, LS || ES || ER || XS). */
	poly1305_init(&pctx, e->ak3);
	poly1305_update(&pctx, p[0], 32);
	poly1305_update(&pctx, p[1], 32);
	poly1305_update(&pctx, p[2], 32);
	poly1305_update(&pctx, p[3], 32);
	poly1305_final(&pctx, e->tag3);

	printf("All numbers encoded as little-endian byte-arrays:\n");
	printf("request: ");
	for (i = 0; i < 32; ++i)
		printf("%02x", p[1][i]);
	printf("\n");
	printf("response: ");
	for (i = 0; i < 32; ++i)
		printf("%02x", p[2][i]);
	printf(" ");
	for (i = 0; i < 16; ++i)
		printf("%02x", e->tag2[i]);
	printf("\n");
	printf("confirmation: ");
	for (i = 0; i < 32; ++i)
		printf("%02x", p[3][i]);
	printf(" ");
	for (i = 0; i < 16; ++i)
		printf("%02x", e->tag3[i]);
	printf("\n");

	for (i = 0; i < 4; ++i)
		free(p[i]);
}

int main()
{
	static struct endpoint e;

	bn_init();

	init_endpoint(&e);
	shared_secret(&e);
	free_endpoint(&e);
	bn_fini();
	return 0;
}
