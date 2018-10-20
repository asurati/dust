/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>

#include <rndm.h>

#include <sys/ec.h>

static void ec_mont_point_print(const struct ec_mont *ecm,
				const struct ec_point *a)
{
	struct bn *t;

	/* Convert to normal for printing. */
	t = bn_new_copy(a->x);
	bn_from_mont(ecm->mctx, t);
	bn_print("x:", t);
	bn_free(t);

	t = bn_new_copy(a->z);
	bn_from_mont(ecm->mctx, t);
	bn_print("z:", t);
	bn_free(t);
}

static void ec_mont_point_free(struct ec_point *a)
{
	bn_free(a->x);
	bn_free(a->z);
	free(a);
}

static struct ec_point *ec_mont_point_new_copy(const struct ec_point *a)
{
	struct ec_point *b;
	b = malloc(sizeof(*b));
	assert(b);
	b->x = bn_new_copy(a->x);
	b->z = bn_new_copy(a->z);
	return b;
}

static void ec_mont_free(struct ec_mont *ecm)
{
	if (ecm->prime != BN_INVALID)
		bn_free(ecm->prime);
	if (ecm->a != BN_INVALID)
		bn_free(ecm->a);
	if (ecm->b != BN_INVALID)
		bn_free(ecm->b);
	if (ecm->order != BN_INVALID)
		bn_free(ecm->order);
	if (ecm->cnst != BN_INVALID)
		bn_free(ecm->cnst);
	if (ecm->gen.x != BN_INVALID)
		bn_free(ecm->gen.x);
	if (ecm->gen.z != BN_INVALID)
		bn_free(ecm->gen.z);
	if (ecm->mctx)
		bn_ctx_mont_free(ecm->mctx);

	/* ecm freed by the wrapper. */
}

static struct ec *ec_mont_new(const struct ec_mont_params *p)
{
	int i;
	struct ec *ec;
	struct ec_mont *ecm;
	struct bn *t[9];

	assert(p != NULL);
	ec = malloc(sizeof(*ec));
	if (ec == NULL)
		goto err0;

	ec->form = ECF_MONTGOMERY;
	ecm = &ec->u.mont;

	ecm->prime = ecm->a = ecm->b = ecm->order = BN_INVALID;
	ecm->gen.x = ecm->gen.y = ecm->gen.z = BN_INVALID;

	/*
	 * Order and Prime are kept as regular numbers.
	 * The rest are converted into the Montgomery form.
	 */

	t[0] = bn_new_from_string(p->prime, 16);
	t[1] = bn_new_from_string(p->a, 16);
	t[2] = bn_new_from_string(p->b, 16);
	t[3] = bn_new_from_string(p->gx, 16);
	t[4] = bn_new_from_string("1", 16);
	t[5] = bn_new_from_string(p->order, 16);
	t[6] = bn_new_from_string(p->a, 16);
	t[7] = bn_new_from_string("2", 16);
	t[8] = bn_new_from_string("4", 16);

	for (i = 0; i < 9; ++i)
		if (t[i] == BN_INVALID)
			goto err1;

	ecm->mctx = bn_ctx_mont_new(t[0]);
	if (ecm->mctx == NULL)
		goto err1;

	bn_add(t[6], t[7]);	/* a + 2 */
	bn_mod_inv(t[8], t[0]);	/* inv(4). */
	bn_mul(t[6], t[8]);
	bn_mod(t[6], t[0]);

	bn_free(t[7]);
	bn_free(t[8]);

	ecm->prime	= t[0];
	ecm->a		= t[1];
	ecm->b		= t[2];
	ecm->gen.x	= t[3];
	ecm->gen.z	= t[4];
	ecm->order	= t[5];
	ecm->cnst	= t[6];

	bn_to_mont(ecm->mctx, ecm->a);
	bn_to_mont(ecm->mctx, ecm->b);
	bn_to_mont(ecm->mctx, ecm->gen.x);
	bn_to_mont(ecm->mctx, ecm->gen.z);
	bn_to_mont(ecm->mctx, ecm->cnst);
	return ec;
err1:
	for (i = 0; i < 9; ++i)
		if (t[i] != BN_INVALID)
			bn_free(t[i]);
	ec_mont_free(ecm);
	free(ec);
err0:
	return EC_INVALID;
}

/* All co-ordinates in projective, Montgomery form. */

/* http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html */
static void ec_mont_dbl(const struct ec_mont *ecm, struct ec_point *a)
{
	struct bn *t[4];

	t[0] = bn_new_copy(a->x);
	bn_add_mont(ecm->mctx, t[0], a->z);
	bn_mul_mont(ecm->mctx, t[0], t[0]);	/* (x + z)^2 */

	t[1] = bn_new_copy(a->x);
	bn_sub_mont(ecm->mctx, t[1], a->z);
	bn_mul_mont(ecm->mctx, t[1], t[1]);	/* (x - z)^2 */

	t[2] = bn_new_copy(t[0]);
	bn_sub_mont(ecm->mctx, t[2], t[1]);	/* diff of sqr */

	bn_mul_mont(ecm->mctx, t[0], t[1]);	/* mul of sqr */

	t[3] = bn_new_copy(t[2]);
	bn_mul_mont(ecm->mctx, t[3], ecm->cnst);
	bn_add_mont(ecm->mctx, t[3], t[1]);
	bn_mul_mont(ecm->mctx, t[3], t[2]);

	bn_free(a->x);
	bn_free(a->z);
	bn_free(t[1]);
	bn_free(t[2]);

	a->x = t[0];
	a->z = t[3];
}

/* All co-ordinates in projective, Montgomery form. */

/*
 * http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html
 * diffadd-dadd-1987-m-3
 */
static void ec_mont_diffadd(const struct ec_mont *ecm, struct ec_point *a,
			    const struct ec_point *b, const struct ec_point *c)
{
	struct bn *t[8];

	t[0] = bn_new_copy(b->x);
	bn_add_mont(ecm->mctx, t[0], b->z);
	t[1] = bn_new_copy(b->x);
	bn_sub_mont(ecm->mctx, t[1], b->z);

	t[2] = bn_new_copy(c->x);
	bn_add_mont(ecm->mctx, t[2], c->z);
	t[3] = bn_new_copy(c->x);
	bn_sub_mont(ecm->mctx, t[3], c->z);

	bn_mul_mont(ecm->mctx, t[3], t[0]);
	bn_mul_mont(ecm->mctx, t[2], t[1]);

	t[4] = bn_new_copy(t[3]);
	bn_add_mont(ecm->mctx, t[4], t[2]);
	bn_mul_mont(ecm->mctx, t[4], t[4]);
	t[5] = bn_new_copy(t[3]);
	bn_sub_mont(ecm->mctx, t[5], t[2]);
	bn_mul_mont(ecm->mctx, t[5], t[5]);

	bn_mul_mont(ecm->mctx, t[4], a->z);
	bn_mul_mont(ecm->mctx, t[5], a->x);

	bn_free(a->x);
	bn_free(a->z);
	bn_free(t[0]);
	bn_free(t[1]);
	bn_free(t[2]);
	bn_free(t[3]);

	a->x = t[4];
	a->z = t[5];
}

static void ec_mont_point_normalize(const struct ec_mont *ecm,
				    struct ec_point *a)
{
	/*
	 * Montgomery modular inverse.
	 * For now, convert to normal, calculate, and convert back to
	 * Montgomery form.
	 */
	bn_from_mont(ecm->mctx, a->x);
	bn_from_mont(ecm->mctx, a->z);

	/*
	 * The inverse does not exist for a point with a->z == 0, or
	 * the point of infinity.
	 */
	assert(bn_mod_inv(a->z, ecm->prime) == 1);
	bn_mul(a->x, a->z);
	bn_mod(a->x, ecm->prime);

	bn_free(a->z);
	a->z = bn_new_from_string("1", 16);

	bn_to_mont(ecm->mctx, a->x);
	bn_to_mont(ecm->mctx, a->z);
}

/* All co-ordinates in projective, Montgomery form. */
/* http://cage.ugent.be/waifi/talks/Farashahi.pdf */
static void ec_mont_scale(const struct ec_mont *ecm, struct ec_point *a,
			  const struct bn *b)
{
	int i, msb;
	struct ec_point *pt[3];

	pt[0] = ec_mont_point_new_copy(a);
	pt[1] = ec_mont_point_new_copy(a);

	ec_mont_dbl(ecm, pt[1]);
	msb = bn_msb(b);

	for (i = msb - 1; i >= 0; --i) {
		/* Difference between pt[0] and pt[1] is always == a. */
		pt[2] = ec_mont_point_new_copy(a);
		ec_mont_diffadd(ecm, pt[2], pt[0], pt[1]);
		if (bn_test_bit(b, i) == 0) {
			ec_mont_dbl(ecm, pt[0]);
			ec_mont_point_free(pt[1]);
			pt[1] = pt[2];
		} else {
			ec_mont_dbl(ecm, pt[1]);
			ec_mont_point_free(pt[0]);
			pt[0] = pt[2];
		}
	}
	ec_mont_point_free(pt[1]);
	bn_free(a->x);
	bn_free(a->z);

	a->x = pt[0]->x;
	a->z = pt[0]->z;
	free(pt[0]);
	ec_mont_point_normalize(ecm, a);
}

struct ec_point *ec_mont_gen_pair(const struct ec_mont *ecm, struct bn **priv)
{
	int nbits, nbytes;
	uint8_t *bytes;
	struct bn *t;
	struct ec_point *pub;

	nbits = bn_msb(ecm->prime) + 1;
	nbytes = (nbits + 7) >> 3;
	bytes = malloc(nbytes);
	assert(bytes);

	/* TODO more efficient way? */
	for (;;) {
		rndm_fill(bytes, nbits);
		t = bn_new_from_bytes(bytes, nbytes);
		/* TODO check for zero. */
		if (bn_cmp_abs(t, ecm->prime) < 0)
			break;
		bn_free(t);
	}
	*priv = t;
	pub = ec_mont_point_new_copy(&ecm->gen);
	ec_mont_scale(ecm, pub, t);
	return pub;
}











void ec_point_print(const struct ec *ec, const struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_point_print(&ec->u.mont, a);
		break;
	default:
		assert(0);
	}
}

void ec_point_free(const struct ec *ec, struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_point_free(a);
		break;
	default:
		assert(0);
	}
}

struct ec_point *ec_point_new_copy(const struct ec *ec,
				   const struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		return ec_mont_point_new_copy(a);
		break;
	default:
		assert(0);
	}
	return EC_POINT_INVALID;
}

void ec_scale(const struct ec *ec, struct ec_point *a, const struct bn *b)
{
	assert(ec != EC_INVALID);
	assert(b != BN_INVALID);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_scale(&ec->u.mont, a, b);
		break;
	default:
		assert(0);
	}
}

struct ec_point *ec_gen_pair(const struct ec *ec, struct bn **priv)
{
	assert(ec != EC_INVALID);
	assert(priv);
	assert(*priv == BN_INVALID);

	switch (ec->form) {
	case ECF_MONTGOMERY:
		return ec_mont_gen_pair(&ec->u.mont, priv);
	default:
		assert(0);
	}
	return EC_POINT_INVALID;
}

void ec_free(struct ec *ec)
{
	assert(ec != EC_INVALID);

	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_free(&ec->u.mont);
		break;
	default:
		assert(0);
	}
	free(ec);
}

struct ec *ec_new_montgomery(const struct ec_mont_params *p)
{
	assert(p != NULL);
	return ec_mont_new(p);
}
