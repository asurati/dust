/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <rndm.h>
#include <sha2.h>

#include <sys/ec.h>

/* Numbers as big-endian strings. */
const char *c25519_prime_be	=
"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed";
const char *c25519_a_be		= "76d06";	// hex(486662)
const char *c25519_b_be		= "1";
const char *c25519_gx_be	= "9";
const char *c25519_order_be	=
"1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed";

const char *ed25519_a_be =
"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffec";
const char *ed25519_d_be =
"52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
const char *ed25519_gx_be =
"216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
const char *ed25519_gy_be =
"6666666666666666666666666666666666666666666666666666666666666658";

static struct bn *ec_mont_point_x(const struct ec_mont *ecm,
				  const struct ec_point *a)
{
	struct bn *t;

	t = bn_new_copy(a->x);
	bn_from_mont(ecm->mctx, t);
	return t;
}

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

/* TODO check validity of a as a point on the curve. */
static struct ec_point *ec_mont_point_new(const struct ec_mont *ecm,
					  const struct bn *x,
					  const struct bn *y,
					  const struct bn *z)
{
	struct ec_point *b;

	assert(x != BN_INVALID);

	b = malloc(sizeof(*b));
	assert(b);
	b->x = bn_new_copy(x);
	if (z != BN_INVALID)
		b->z = bn_new_copy(z);
	else
		b->z = bn_new_from_int(1);
	bn_to_mont(ecm->mctx, b->x);
	bn_to_mont(ecm->mctx, b->z);
	return b;
	(void)y;
}

/* TODO check validity of a as a point on the curve. */
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

	t[0] = bn_new_from_string_be(p->prime, 16);
	t[1] = bn_new_from_string_be(p->a, 16);
	t[2] = bn_new_from_string_be(p->b, 16);
	t[3] = bn_new_from_string_be(p->gx, 16);
	t[4] = bn_new_from_int(1);
	t[5] = bn_new_from_string_be(p->order, 16);
	t[6] = bn_new_from_string_be(p->a, 16);
	t[7] = bn_new_from_int(2);
	t[8] = bn_new_from_int(4);

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
	a->z = bn_new_from_string_be("1", 16);

	bn_to_mont(ecm->mctx, a->x);
	bn_to_mont(ecm->mctx, a->z);
}

/* All co-ordinates in projective, Montgomery form. */
/* http://cage.ugent.be/waifi/talks/Farashahi.pdf */
static void ec_mont_scale(const struct ec_mont *ecm, struct ec_point **_a,
			  const struct bn *b)
{
	int i, msb;
	struct ec_point *pt[3], *a;

	assert(_a != NULL);
	a = *_a;
	if (a == EC_POINT_INVALID)
		a = ec_mont_point_new_copy(&ecm->gen);

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
	ec_mont_point_free(a);
	ec_mont_point_normalize(ecm, pt[0]);
	*_a = pt[0];
}








static struct bn *ec_edwards_point_y(const struct ec_edwards *ece,
				     const struct ec_point *a)
{
	struct bn *t;

	t = bn_new_copy(a->y);
	bn_from_mont(ece->mctx, t);
	return t;
}

static struct bn *ec_edwards_point_x(const struct ec_edwards *ece,
				     const struct ec_point *a)
{
	struct bn *t;

	t = bn_new_copy(a->x);
	bn_from_mont(ece->mctx, t);
	return t;
}

static void ec_edwards_point_print(const struct ec_edwards *ece,
				   const struct ec_point *a)
{
	struct bn *t;

	/* Convert to normal for printing. */
	t = bn_new_copy(a->x);
	bn_from_mont(ece->mctx, t);
	bn_print("x:", t);
	bn_free(t);

	t = bn_new_copy(a->y);
	bn_from_mont(ece->mctx, t);
	bn_print("y:", t);
	bn_free(t);

	t = bn_new_copy(a->z);
	bn_from_mont(ece->mctx, t);
	bn_print("z:", t);
	bn_free(t);
}

static void ec_edwards_point_free(struct ec_point *a)
{
	bn_free(a->x);
	bn_free(a->y);
	bn_free(a->z);
	free(a);
}

/*
 * TODO check validity of a as a point on the curve.
 */
static struct ec_point *ec_edwards_point_new(const struct ec_edwards *ece,
					     const struct bn *x,
					     const struct bn *y,
					     const struct bn *z)
{
	struct ec_point *b;

	assert(x != BN_INVALID);
	assert(y != BN_INVALID);

	b = malloc(sizeof(*b));
	assert(b);
	b->x = bn_new_copy(x);
	b->y = bn_new_copy(x);
	if (z != BN_INVALID)
		b->z = bn_new_copy(z);
	else
		b->z = bn_new_from_int(1);
	bn_to_mont(ece->mctx, b->x);
	bn_to_mont(ece->mctx, b->y);
	bn_to_mont(ece->mctx, b->z);
	return b;
}

/* TODO check validity of a as a point on the curve. */
static struct ec_point *ec_edwards_point_new_copy(const struct ec_point *a)
{
	struct ec_point *b;
	b = malloc(sizeof(*b));
	assert(b);
	b->x = bn_new_copy(a->x);
	b->y = bn_new_copy(a->y);
	b->z = bn_new_copy(a->z);
	return b;
}

static void ec_edwards_point_normalize(const struct ec_edwards *ece,
				       struct ec_point *a)
{
	/*
	 * Montgomery modular inverse.
	 * For now, convert to normal, calculate, and convert back to
	 * Montgomery form.
	 */
	bn_from_mont(ece->mctx, a->x);
	bn_from_mont(ece->mctx, a->y);
	bn_from_mont(ece->mctx, a->z);

	/*
	 * The inverse does not exist for a point with a->z == 0, or
	 * the point of infinity.
	 */
	assert(bn_mod_inv(a->z, ece->prime) == 1);
	bn_mul(a->x, a->z);
	bn_mul(a->y, a->z);
	bn_mod(a->x, ece->prime);
	bn_mod(a->y, ece->prime);

	bn_free(a->z);
	a->z = bn_new_from_string_be("1", 16);

	bn_to_mont(ece->mctx, a->x);
	bn_to_mont(ece->mctx, a->y);
	bn_to_mont(ece->mctx, a->z);
}

/*
 * All co-ordinates in projective, Montgomery form. mdbl-2008-bbjlp.
 * Leaves the Z coordinate set to 1.
 */
static void ec_edwards_dbl(const struct ec_edwards *ece, struct ec_point *a)
{
	struct bn *t[6], *two;

	t[0] = bn_new_copy(a->x);
	bn_add_mont(ece->mctx, t[0], a->y);
	bn_mul_mont(ece->mctx, t[0], t[0]);	/* B = (x + y)^2 */
	t[1] = bn_new_copy(a->x);
	bn_mul_mont(ece->mctx, t[1], t[1]);	/* C = x^2 */
	t[2] = bn_new_copy(a->y);
	bn_mul_mont(ece->mctx, t[2], t[2]);	/* D = y^2 */

	t[3] = bn_new_copy(ece->a);
	bn_mul_mont(ece->mctx, t[3], t[1]);	/* E = a * C */

	t[4] = bn_new_copy(t[3]);
	bn_add_mont(ece->mctx, t[4], t[2]);	/* F = E + D */

	two = bn_new_from_int(2);
	bn_to_mont(ece->mctx, two);
	t[5] = bn_new_copy(t[4]);
	bn_sub_mont(ece->mctx, t[5], two);	/* F - 2 */
	bn_free(two);

	bn_sub_mont(ece->mctx, t[0], t[1]);
	bn_sub_mont(ece->mctx, t[0], t[2]);
	bn_mul_mont(ece->mctx, t[0], t[5]);	/* X3 = (B-C-D) * (F-2) */

	bn_sub_mont(ece->mctx, t[3], t[2]);
	bn_mul_mont(ece->mctx, t[3], t[4]);	/* Y3 = (E - D) * F */

	bn_mul_mont(ece->mctx, t[5], t[4]);	/* Z3 = (F - 2) * F */

	bn_free(a->x);
	bn_free(a->y);
	bn_free(a->z);
	bn_free(t[1]);
	bn_free(t[2]);
	bn_free(t[4]);

	a->x = t[0];
	a->y = t[3];
	a->z = t[5];
	ec_edwards_point_normalize(ece, a);
}

/*
 * All co-ordinates in projective, Montgomery form. mmadd-2008-bbjlp.
 * Leaves the Z coordinate as 1.
 */
static void ec_edwards_add(const struct ec_edwards *ece, struct ec_point *a,
			   const struct ec_point *b)
{
	struct bn *t[7], *one;

	t[0] = bn_new_copy(a->x);
	bn_mul_mont(ece->mctx, t[0], b->x);	/* C = X1 * X2 */

	t[1] = bn_new_copy(a->y);
	bn_mul_mont(ece->mctx, t[1], b->y);	/* D = Y1 * Y2 */

	t[2] = bn_new_copy(ece->d);
	bn_mul_mont(ece->mctx, t[2], t[0]);
	bn_mul_mont(ece->mctx, t[2], t[1]);	/* E = d * C * D */

	one = bn_new_from_int(1);
	bn_to_mont(ece->mctx, one);

	t[3] = bn_new_copy(one);
	bn_sub_mont(ece->mctx, t[3], t[2]);	/* 1 - E */
	t[4] = bn_new_copy(a->x);
	bn_add_mont(ece->mctx, t[4], a->y);	/* X1 + Y1 */
	t[5] = bn_new_copy(b->x);
	bn_add_mont(ece->mctx, t[5], b->y);	/* X2 + Y2 */
	bn_mul_mont(ece->mctx, t[4], t[5]);
	bn_sub_mont(ece->mctx, t[4], t[0]);
	bn_sub_mont(ece->mctx, t[4], t[1]);
	bn_mul_mont(ece->mctx, t[3], t[4]);	/* X3 */

	t[6] = bn_new_copy(one);
	bn_add_mont(ece->mctx, t[6], t[2]);	/* 1 + E */
	bn_mul_mont(ece->mctx, t[0], ece->a);
	bn_sub_mont(ece->mctx, t[1], t[0]);
	bn_mul_mont(ece->mctx, t[6], t[1]);	/* Y3 */

	bn_mul_mont(ece->mctx, t[2], t[2]);
	bn_sub_mont(ece->mctx, one, t[2]);	/* Z3 */

	bn_free(a->x);
	bn_free(a->y);
	bn_free(a->z);
	bn_free(t[0]);
	bn_free(t[1]);
	bn_free(t[2]);
	bn_free(t[4]);
	bn_free(t[5]);

	a->x = t[3];
	a->y = t[6];
	a->z = one;
	ec_edwards_point_normalize(ece, a);
}


/* All co-ordinates in projective, Montgomery form. */
static void ec_edwards_scale(const struct ec_edwards *ece,
			     struct ec_point **_a, const struct bn *b)
{
	int i, msb;
	struct ec_point *pt, *a;

	assert(_a != NULL);
	assert(!bn_is_zero(b));

	a = *_a;
	if (a == EC_POINT_INVALID)
		a = ec_edwards_point_new_copy(&ece->gen);

	pt = ec_edwards_point_new_copy(a);
	msb = bn_msb(b);
	assert(msb >= 0);

	for (i = msb - 1; i >= 0; --i) {
		ec_edwards_dbl(ece, pt);
		if (bn_test_bit(b, i) == 1)
			ec_edwards_add(ece, pt, a);
	}
	ec_edwards_point_free(a);
	*_a = pt;
}

static void ec_edwards_free(struct ec_edwards *ece)
{
	if (ece->prime != BN_INVALID)
		bn_free(ece->prime);
	if (ece->a != BN_INVALID)
		bn_free(ece->a);
	if (ece->d != BN_INVALID)
		bn_free(ece->d);
	if (ece->order != BN_INVALID)
		bn_free(ece->order);
	if (ece->gen.x != BN_INVALID)
		bn_free(ece->gen.x);
	if (ece->gen.y != BN_INVALID)
		bn_free(ece->gen.y);
	if (ece->gen.z != BN_INVALID)
		bn_free(ece->gen.z);
	if (ece->mctx)
		bn_ctx_mont_free(ece->mctx);

	/* ece freed by the wrapper. */
}

static struct ec *ec_edwards_new(const struct ec_edwards_params *p)
{
	int i;
	struct ec *ec;
	struct ec_edwards *ece;
	struct bn *t[7];

	assert(p != NULL);
	ec = malloc(sizeof(*ec));
	if (ec == NULL)
		goto err0;

	ec->form = ECF_EDWARDS;
	ece = &ec->u.edwards;

	ece->prime = ece->a = ece->d = ece->order = BN_INVALID;
	ece->gen.x = ece->gen.y = ece->gen.z = BN_INVALID;

	/*
	 * Order and Prime are kept as regular numbers.
	 * The rest are converted into the Montgomery form.
	 */

	t[0] = bn_new_from_string_be(p->prime, 16);
	t[1] = bn_new_from_string_be(p->a, 16);
	t[2] = bn_new_from_string_be(p->d, 16);
	t[3] = bn_new_from_string_be(p->gx, 16);
	t[4] = bn_new_from_string_be(p->gy, 16);
	t[5] = bn_new_from_int(1);	/* Projective coordinates. */
	t[6] = bn_new_from_string_be(p->order, 16);

	for (i = 0; i < 7; ++i)
		if (t[i] == BN_INVALID)
			goto err1;

	ece->mctx = bn_ctx_mont_new(t[0]);
	if (ece->mctx == NULL)
		goto err1;

	ece->prime	= t[0];
	ece->a		= t[1];
	ece->d		= t[2];
	ece->gen.x	= t[3];
	ece->gen.y	= t[4];
	ece->gen.z	= t[5];
	ece->order	= t[6];

	bn_to_mont(ece->mctx, ece->a);
	bn_to_mont(ece->mctx, ece->d);
	bn_to_mont(ece->mctx, ece->gen.x);
	bn_to_mont(ece->mctx, ece->gen.y);
	bn_to_mont(ece->mctx, ece->gen.z);
	return ec;
err1:
	for (i = 0; i < 7; ++i)
		if (t[i] != BN_INVALID)
			bn_free(t[i]);
	ec_edwards_free(ece);
	free(ec);
err0:
	return EC_INVALID;
}










struct bn *ec_point_y(const struct ec *ec, const struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	assert(a->x != BN_INVALID);

	switch (ec->form) {
	case ECF_EDWARDS:
		return ec_edwards_point_y(&ec->u.edwards, a);
	default:
		assert(0);
	}
	return BN_INVALID;
}

struct bn *ec_point_x(const struct ec *ec, const struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	assert(a->x != BN_INVALID);

	switch (ec->form) {
	case ECF_MONTGOMERY:
		return ec_mont_point_x(&ec->u.mont, a);
	case ECF_EDWARDS:
		return ec_edwards_point_x(&ec->u.edwards, a);
	default:
		assert(0);
	}
	return BN_INVALID;
}

void ec_point_print(const struct ec *ec, const struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_point_print(&ec->u.mont, a);
		break;
	case ECF_EDWARDS:
		ec_edwards_point_print(&ec->u.edwards, a);
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
	case ECF_EDWARDS:
		ec_edwards_point_free(a);
		break;
	default:
		assert(0);
	}
}

struct ec_point	*ec_point_new(const struct ec *ec, const struct bn *x,
			      const struct bn *y, const struct bn *z)
{
	assert(ec != EC_INVALID);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		return ec_mont_point_new(&ec->u.mont, x, y, z);
	case ECF_EDWARDS:
		return ec_edwards_point_new(&ec->u.edwards, x, y, z);
	default:
		assert(0);
	}
	return EC_POINT_INVALID;
}

struct ec_point *ec_point_new_copy(const struct ec *ec,
				   const struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		return ec_mont_point_new_copy(a);
	case ECF_EDWARDS:
		return ec_edwards_point_new_copy(a);
	default:
		assert(0);
	}
	return EC_POINT_INVALID;
}

void ec_scale(const struct ec *ec, struct ec_point **a, const struct bn *b)
{
	assert(ec != EC_INVALID);
	assert(b != BN_INVALID);
	assert(a != NULL);
	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_scale(&ec->u.mont, a, b);
		break;
	case ECF_EDWARDS:
		ec_edwards_scale(&ec->u.edwards, a, b);
		break;
	default:
		assert(0);
	}
}

void ec_free(struct ec *ec)
{
	assert(ec != EC_INVALID);

	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_free(&ec->u.mont);
		break;
	case ECF_EDWARDS:
		ec_edwards_free(&ec->u.edwards);
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

struct ec *ec_new_edwards(const struct ec_edwards_params *p)
{
	assert(p != NULL);
	return ec_edwards_new(p);
}












struct edc *edc_new_verify(const uint8_t *pub)
{
	struct edc *edc;
	struct ec_mont_params emp;

	edc = malloc(sizeof(*edc));
	assert(edc);

	emp.prime	= c25519_prime_be;
	emp.a		= c25519_a_be;
	emp.b		= c25519_b_be;
	emp.gx		= c25519_gx_be;
	emp.order	= c25519_order_be;

	edc->to_sign = 0;
	edc->ec = ec_new_montgomery(&emp);
	memcpy(edc->pub, pub, 32);
	return edc;
}

static void edc_encode(const struct edc *edc, uint8_t *out,
		       const struct ec_point *pt)
{
	int msb, n;
	uint8_t *bytes;
	struct bn *x, *y;

	x = ec_point_x(edc->ec, pt);
	if (bn_is_zero(x))
		msb = 0;
	else
		msb = bn_test_bit(x, 0);
	bn_free(x);

	y = ec_point_y(edc->ec, pt);
	bytes = bn_to_bytes_le(y, &n);
	bn_free(y);

	assert(n <= 32);
	memcpy(out, bytes, n);
	memset(out + n, 0, 32 - n);
	if (msb)
		out[31] |= 0x80;
	free(bytes);
}

/* static local variables here and elsewhere imply multithread nonsafety. */
struct edc *edc_new_sign(const uint8_t *priv)
{
	struct edc *edc;
	struct ec_edwards_params eep;
	struct bn *t;
	struct ec_point *pt;
	static struct sha512_ctx ctx;

	edc = malloc(sizeof(*edc));
	assert(edc);

	eep.prime	= c25519_prime_be;
	eep.order	= c25519_order_be;
	eep.a		= ed25519_a_be;
	eep.d		= ed25519_d_be;
	eep.gx		= ed25519_gx_be;
	eep.gy		= ed25519_gy_be;

	edc->to_sign = 1;
	edc->ec = ec_new_edwards(&eep);

	sha512_init(&ctx);
	sha512_update(&ctx, priv, 32);
	sha512_final(&ctx, edc->priv_dgst);

	/* Prune. */
	edc->priv_dgst[0]  &= 0xf8;
	edc->priv_dgst[31] &= 0x7f;
	edc->priv_dgst[31] |= 0x40;

	/* Scale. */
	pt = EC_POINT_INVALID;
	t = bn_new_from_bytes_le(edc->priv_dgst, 32);
	ec_scale(edc->ec, &pt, t);
	bn_free(t);

	/* Encode. */
	edc_encode(edc, edc->pub, pt);
	ec_point_free(edc->ec, pt);

	return edc;
}

void edc_free(struct edc *edc)
{
	assert(edc != EDC_INVALID);
	ec_free(edc->ec);
	free(edc);
}

void edc_sign(const struct edc *edc, uint8_t *tag, const uint8_t *msg,
	      int mlen)
{
	int n;
	uint8_t *bytes;
	struct bn *ord, *r, *k, *s;
	struct ec_point *pt;
	static struct sha512_ctx ctx;
	static uint8_t dgst[SHA512_DIGEST_LEN];

	assert(edc != EDC_INVALID);
	assert(tag);
	assert(mlen >= 0);
	assert(edc->to_sign == 1);

	if (msg == NULL)
		mlen = 0;

	memset(tag, 0, 64);
	ord = bn_new_from_string_be(c25519_order_be, 16);

	sha512_init(&ctx);
	sha512_update(&ctx, &edc->priv_dgst[32], 32);
	sha512_update(&ctx, msg, mlen);
	sha512_final(&ctx, dgst);

	/* r == little-endian integer out of dgst. */
	r = bn_new_from_bytes_le(dgst, SHA512_DIGEST_LEN);
	bn_mod(r, ord);

	/* R = [r]B */
	pt = EC_POINT_INVALID;
	ec_scale(edc->ec, &pt, r);
	edc_encode(edc, dgst, pt);
	ec_point_free(edc->ec, pt);
	memcpy(tag, dgst, 32);			/* output R */

	sha512_init(&ctx);
	sha512_update(&ctx, dgst, 32);		/* R */
	sha512_update(&ctx, edc->pub, 32);	/* A */
	sha512_update(&ctx, msg, mlen);		/* M */
	sha512_final(&ctx, dgst);

	/* k == little-endian integer out of dgst. */
	k = bn_new_from_bytes_le(dgst, SHA512_DIGEST_LEN);
	bn_mod(k, ord);

	s = bn_new_from_bytes_le(edc->priv_dgst, 32);
	bn_mul(s, k);
	bn_add(s, r);
	bn_mod(s, ord);				/* S */

	bytes = bn_to_bytes_le(s, &n);
	memcpy(tag + 32, bytes, n);		/* output S */

	free(bytes);
	bn_free(r);
	bn_free(k);
	bn_free(s);
	bn_free(ord);
}
