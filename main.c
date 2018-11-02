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
	struct bn *espubx, *lspubx, *erpubx, *lrpubx;

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
	bn_free(e->espubx);
	bn_free(e->lspubx);
	ec_point_free(e->ec, e->espub);
	ec_point_free(e->ec, e->lspub);

	bn_free(e->erpriv);
	bn_free(e->lrpriv);
	bn_free(e->erpubx);
	bn_free(e->lrpubx);
	ec_point_free(e->ec, e->erpub);
	ec_point_free(e->ec, e->lrpub);

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
	e->espubx = ec_point_x(ec, e->espub);
	e->lspubx = ec_point_x(ec, e->lspub);

	e->erpriv = bn_rand();
	e->lrpriv = bn_rand();
	e->erpub = ec_gen_public(ec, e->erpriv);
	e->lrpub = ec_gen_public(ec, e->lrpriv);
	e->erpubx = ec_point_x(ec, e->erpub);
	e->lrpubx = ec_point_x(ec, e->lrpub);
	e->ec = ec;
}

const uint8_t zeroes[64];
void calc_key(const struct ec *ec, uint8_t *out, const struct ec_point *pub,
	      const struct bn *priv, int nv)
{
	struct ec_point *ep;
	struct bn *t;
	uint8_t *p;
	int n;
	static uint8_t nonce[16];

	memset(nonce, 0, sizeof(nonce));
	ep = ec_point_new_copy(ec, pub);
	ec_scale(ec, ep, priv);
	t = ec_point_x(ec, ep);
	ec_point_free(ec, ep);
	p = bn_to_bytes_le(t, &n);
	bn_free(t);
	assert(n == 32);

	nonce[0] = nv;
	hchacha20(out, p, nonce);
	free(p);
}

void shared_secret(struct endpoint *e)
{
	uint8_t *s[4];
	int i, n;
	static uint8_t nonce[16];
	static uint8_t k1[32], k2[32], k3[32];
	static struct chacha20_ctx ctx;
	static struct poly1305_ctx pctx;

	memset(nonce, 0, sizeof(nonce));

	/* X25519(scalar, point) == ec_scale(ec, point, scalar). */

	/* k1 = hchacha20(X25519(ES, ER), 0). */
	calc_key(e->ec, k1, e->erpub, e->espubx, 0);

	/* k2 = hchacha20(X25519(ES, LR), 1). */
	calc_key(e->ec, k2, e->lrpub, e->espubx, 1);

	/* k3 = hchacha20(X25519(LS, ER), 2). */
	calc_key(e->ec, k3, e->erpub, e->lspubx, 2);

	for (i = 0; i < 32; ++i)
		k2[i] ^= k1[i];

	for (i = 0; i < 32; ++i)
		k3[i] ^= k2[i];

	chacha20_init(&ctx, k2, zeroes, 0);
	chacha20_enc(&ctx, e->ak2, zeroes, 32);
	chacha20_enc(&ctx, e->ek2, zeroes, 32);
	chacha20_init(&ctx, k3, zeroes, 0);
	chacha20_enc(&ctx, e->ak3, zeroes, 32);
	chacha20_enc(&ctx, e->ek3, zeroes, 32);

	s[0] = bn_to_bytes_le(e->lrpubx, &n);
	assert(n == 32);
	s[1] = bn_to_bytes_le(e->espubx, &n);
	assert(n == 32);
	s[2] = bn_to_bytes_le(e->erpubx, &n);
	assert(n == 32);
	s[3] = bn_to_bytes_le(e->lspubx, &n);
	assert(n == 32);
	for (i = 0; i < 32; ++i)
		s[3][i] ^= e->ek2[i];

	poly1305_init(&pctx, e->ak2);
	poly1305_update(&pctx, s[0], 32);
	poly1305_update(&pctx, s[1], 32);
	poly1305_update(&pctx, s[2], 32);
	poly1305_final(&pctx, e->tag2);

	poly1305_init(&pctx, e->ak3);
	poly1305_update(&pctx, s[0], 32);
	poly1305_update(&pctx, s[1], 32);
	poly1305_update(&pctx, s[2], 32);
	poly1305_update(&pctx, s[3], 32);
	poly1305_final(&pctx, e->tag3);

	printf("All numbers encoded as little-endian byte-array\n");
	printf("request: ");
	for (i = 0; i < 32; ++i)
		printf("%02x", s[1][i]);
	printf("\n");
	printf("response: ");
	for (i = 0; i < 32; ++i)
		printf("%02x", s[2][i]);
	printf(" ");
	for (i = 0; i < 16; ++i)
		printf("%02x", e->tag2[i]);
	printf("\n");
	printf("confirmation: ");
	for (i = 0; i < 32; ++i)
		printf("%02x", s[3][i]);
	printf(" ");
	for (i = 0; i < 16; ++i)
		printf("%02x", e->tag3[i]);
	printf("\n");

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
