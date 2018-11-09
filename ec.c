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

struct bn *ecm_point_x(const struct ec_mont *ec, const struct ec_point *a)
{
	struct bn *t;

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	t = bn_new_copy(a->x);
	bn_from_mont(ec->mctx, t);
	return t;
}

void ecm_point_print(const struct ec_mont *ec, const struct ec_point *a)
{
	struct bn *t;

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	/* Convert to normal for printing. */
	t = bn_new_copy(a->x);
	bn_from_mont(ec->mctx, t);
	bn_print("x:", t);
	bn_free(t);

	t = bn_new_copy(a->z);
	bn_from_mont(ec->mctx, t);
	bn_print("z:", t);
	bn_free(t);
}

void ecm_point_free(const struct ec_mont *ec, struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	bn_free(a->x);
	bn_free(a->z);
	free(a);
}

/* TODO check validity of the point on the curve. */
struct ec_point *ecm_point_new(const struct ec_mont *ec, const struct bn *x)
{
	struct ec_point *b;

	assert(ec != EC_INVALID);
	assert(x != BN_INVALID);

	b = malloc(sizeof(*b));
	assert(b);

	b->x = bn_new_copy(x);
	b->z = bn_new_from_int(1);
	bn_to_mont(ec->mctx, b->x);
	bn_to_mont(ec->mctx, b->z);
	return b;
}

struct ec_point *ecm_point_new_copy(const struct ec_mont *ec,
				    const struct ec_point *a)
{
	struct ec_point *b;

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	b = malloc(sizeof(*b));
	assert(b);
	b->x = bn_new_copy(a->x);
	b->z = bn_new_copy(a->z);
	return b;
}

void ecm_free(struct ec_mont *ec)
{
	if (ec->prime != BN_INVALID)
		bn_free(ec->prime);
	if (ec->a != BN_INVALID)
		bn_free(ec->a);
	if (ec->b != BN_INVALID)
		bn_free(ec->b);
	if (ec->order != BN_INVALID)
		bn_free(ec->order);
	if (ec->cnst != BN_INVALID)
		bn_free(ec->cnst);
	if (ec->gen.x != BN_INVALID)
		bn_free(ec->gen.x);
	if (ec->gen.z != BN_INVALID)
		bn_free(ec->gen.z);
	if (ec->mctx)
		bn_ctx_mont_free(ec->mctx);
	free(ec);
}

struct ec_mont *ec_new_montgomery(const struct ec_mont_params *p)
{
	int i;
	struct ec_mont *ec;
	struct bn *t[9];

	assert(p != NULL);
	ec = malloc(sizeof(*ec));
	if (ec == NULL)
		goto err0;

	ec->prime = ec->a = ec->b = ec->order = BN_INVALID;
	ec->gen.x = ec->gen.y = ec->gen.z = BN_INVALID;

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

	ec->mctx = bn_ctx_mont_new(t[0]);
	if (ec->mctx == NULL)
		goto err1;

	bn_add(t[6], t[7]);	/* a + 2 */
	bn_mod_inv(t[8], t[0]);	/* inv(4). */
	bn_mul(t[6], t[8]);
	bn_mod(t[6], t[0]);

	bn_free(t[7]);
	bn_free(t[8]);

	ec->prime	= t[0];
	ec->a		= t[1];
	ec->b		= t[2];
	ec->gen.x	= t[3];
	ec->gen.z	= t[4];
	ec->order	= t[5];
	ec->cnst	= t[6];

	bn_to_mont(ec->mctx, ec->a);
	bn_to_mont(ec->mctx, ec->b);
	bn_to_mont(ec->mctx, ec->gen.x);
	bn_to_mont(ec->mctx, ec->gen.z);
	bn_to_mont(ec->mctx, ec->cnst);
	return ec;
err1:
	for (i = 0; i < 9; ++i)
		if (t[i] != BN_INVALID)
			bn_free(t[i]);
	ecm_free(ec);
err0:
	return EC_INVALID;
}

/* All co-ordinates in projective, Montgomery form. */

/* http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html */
void ecm_dbl(const struct ec_mont *ec, struct ec_point *a)
{
	struct bn *t[4];

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	t[0] = bn_new_copy(a->x);
	bn_add_mont(ec->mctx, t[0], a->z);
	bn_mul_mont(ec->mctx, t[0], t[0]);	/* (x + z)^2 */

	t[1] = bn_new_copy(a->x);
	bn_sub_mont(ec->mctx, t[1], a->z);
	bn_mul_mont(ec->mctx, t[1], t[1]);	/* (x - z)^2 */

	t[2] = bn_new_copy(t[0]);
	bn_sub_mont(ec->mctx, t[2], t[1]);	/* diff of sqr */

	bn_mul_mont(ec->mctx, t[0], t[1]);	/* mul of sqr */

	t[3] = bn_new_copy(t[2]);
	bn_mul_mont(ec->mctx, t[3], ec->cnst);
	bn_add_mont(ec->mctx, t[3], t[1]);
	bn_mul_mont(ec->mctx, t[3], t[2]);

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
 *
 * a == diff between b and c
 */
void ecm_diffadd(const struct ec_mont *ec, struct ec_point *a,
		 const struct ec_point *b, const struct ec_point *c)
{
	struct bn *t[8];

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	assert(b != EC_POINT_INVALID);
	assert(c != EC_POINT_INVALID);

	t[0] = bn_new_copy(b->x);
	bn_add_mont(ec->mctx, t[0], b->z);
	t[1] = bn_new_copy(b->x);
	bn_sub_mont(ec->mctx, t[1], b->z);

	t[2] = bn_new_copy(c->x);
	bn_add_mont(ec->mctx, t[2], c->z);
	t[3] = bn_new_copy(c->x);
	bn_sub_mont(ec->mctx, t[3], c->z);

	bn_mul_mont(ec->mctx, t[3], t[0]);
	bn_mul_mont(ec->mctx, t[2], t[1]);

	t[4] = bn_new_copy(t[3]);
	bn_add_mont(ec->mctx, t[4], t[2]);
	bn_mul_mont(ec->mctx, t[4], t[4]);
	t[5] = bn_new_copy(t[3]);
	bn_sub_mont(ec->mctx, t[5], t[2]);
	bn_mul_mont(ec->mctx, t[5], t[5]);

	bn_mul_mont(ec->mctx, t[4], a->z);
	bn_mul_mont(ec->mctx, t[5], a->x);

	bn_free(a->x);
	bn_free(a->z);
	bn_free(t[0]);
	bn_free(t[1]);
	bn_free(t[2]);
	bn_free(t[3]);

	a->x = t[4];
	a->z = t[5];
}

void ecm_point_normalize(const struct ec_mont *ec, struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	/*
	 * Montgomery modular inverse.
	 * For now, convert to normal, calculate, and convert back to
	 * Montgomery form.
	 */
	bn_from_mont(ec->mctx, a->x);
	bn_from_mont(ec->mctx, a->z);

	/*
	 * The inverse does not exist for a point with a->z == 0, or
	 * the point of infinity.
	 */
	assert(bn_mod_inv(a->z, ec->prime) == 1);
	bn_mul(a->x, a->z);
	bn_mod(a->x, ec->prime);

	bn_free(a->z);
	a->z = bn_new_from_string_be("1", 16);

	bn_to_mont(ec->mctx, a->x);
	bn_to_mont(ec->mctx, a->z);
}

/* All co-ordinates in projective, Montgomery form. */
/* http://cage.ugent.be/waifi/talks/Farashahi.pdf */
void ecm_scale(const struct ec_mont *ec, struct ec_point **_a,
	       const struct bn *b)
{
	int i, msb;
	struct ec_point *pt[3], *a;

	assert(ec != EC_INVALID);
	assert(b != BN_INVALID);
	assert(_a != NULL);

	a = *_a;
	if (a == EC_POINT_INVALID)
		a = ecm_point_new_copy(ec, &ec->gen);

	pt[0] = ecm_point_new_copy(ec, a);
	pt[1] = ecm_point_new_copy(ec, a);

	ecm_dbl(ec, pt[1]);
	msb = bn_msb(b);

	for (i = msb - 1; i >= 0; --i) {
		/* Difference between pt[0] and pt[1] is always == a. */
		pt[2] = ecm_point_new_copy(ec, a);
		ecm_diffadd(ec, pt[2], pt[0], pt[1]);
		if (bn_test_bit(b, i) == 0) {
			ecm_dbl(ec, pt[0]);
			ecm_point_free(ec, pt[1]);
			pt[1] = pt[2];
		} else {
			ecm_dbl(ec, pt[1]);
			ecm_point_free(ec, pt[0]);
			pt[0] = pt[2];
		}
	}
	ecm_point_free(ec, pt[1]);
	ecm_point_free(ec, a);
	ecm_point_normalize(ec, pt[0]);
	*_a = pt[0];
}







/* Equal or not equal. */
static int ece_points_equal(const struct ec_edwards *ec,
			    const struct ec_point *a, const struct ec_point *b)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	assert(b != EC_POINT_INVALID);

	return (bn_cmp(a->x, b->x) == 0) && (bn_cmp(a->y, b->y) == 0) &&
		(bn_cmp(a->z, b->z) == 0);
}

struct bn *ece_point_x(const struct ec_edwards *ec, const struct ec_point *a)
{
	struct bn *t;

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	t = bn_new_copy(a->x);
	bn_from_mont(ec->mctx, t);
	return t;
}

struct bn *ece_point_y(const struct ec_edwards *ec, const struct ec_point *a)
{
	struct bn *t;

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	t = bn_new_copy(a->y);
	bn_from_mont(ec->mctx, t);
	return t;
}

void ece_point_print(const struct ec_edwards *ec, const struct ec_point *a)
{
	struct bn *t;

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	/* Convert to normal for printing. */
	t = bn_new_copy(a->x);
	bn_from_mont(ec->mctx, t);
	bn_print("x:", t);
	bn_free(t);

	t = bn_new_copy(a->y);
	bn_from_mont(ec->mctx, t);
	bn_print("y:", t);
	bn_free(t);

	t = bn_new_copy(a->z);
	bn_from_mont(ec->mctx, t);
	bn_print("z:", t);
	bn_free(t);
}

void ece_point_free(const struct ec_edwards *ec, struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	bn_free(a->x);
	bn_free(a->y);
	bn_free(a->z);
	free(a);
}

/*
 * TODO check validity of a as a point on the curve.
 */
struct ec_point *ece_point_new(const struct ec_edwards *ec,
			       const struct bn *x, const struct bn *y)
{
	struct ec_point *b;

	assert(ec != EC_INVALID);
	assert(x != BN_INVALID);
	assert(y != BN_INVALID);

	b = malloc(sizeof(*b));
	assert(b);
	b->x = bn_new_copy(x);
	b->y = bn_new_copy(y);
	b->z = bn_new_from_int(1);
	bn_to_mont(ec->mctx, b->x);
	bn_to_mont(ec->mctx, b->y);
	bn_to_mont(ec->mctx, b->z);
	return b;
}

struct ec_point *ece_point_new_copy(const struct ec_edwards *ec,
				    const struct ec_point *a)
{
	struct ec_point *b;

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	b = malloc(sizeof(*b));
	assert(b);
	b->x = bn_new_copy(a->x);
	b->y = bn_new_copy(a->y);
	b->z = bn_new_copy(a->z);
	return b;
}

void ece_point_normalize(const struct ec_edwards *ec, struct ec_point *a)
{
	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	/*
	 * Montgomery modular inverse.
	 * For now, convert to normal, calculate, and convert back to
	 * Montgomery form.
	 */
	bn_from_mont(ec->mctx, a->x);
	bn_from_mont(ec->mctx, a->y);
	bn_from_mont(ec->mctx, a->z);

	/*
	 * The inverse does not exist for a point with a->z == 0, or
	 * the point of infinity.
	 */
	assert(bn_mod_inv(a->z, ec->prime) == 1);
	bn_mul(a->x, a->z);
	bn_mul(a->y, a->z);
	bn_mod(a->x, ec->prime);
	bn_mod(a->y, ec->prime);

	bn_free(a->z);
	a->z = bn_new_from_string_be("1", 16);

	bn_to_mont(ec->mctx, a->x);
	bn_to_mont(ec->mctx, a->y);
	bn_to_mont(ec->mctx, a->z);
}

/*
 * All co-ordinates in projective, Montgomery form. dbl-2008-bbjlp.
 */
void ece_dbl(const struct ec_edwards *ec, struct ec_point *a)
{
	struct bn *t[7];

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);

	t[0] = bn_new_copy(a->x);
	bn_add_mont(ec->mctx, t[0], a->y);
	bn_mul_mont(ec->mctx, t[0], t[0]);	/* B = (x + y)^2 */
	t[1] = bn_new_copy(a->x);
	bn_mul_mont(ec->mctx, t[1], t[1]);	/* C = x^2 */
	t[2] = bn_new_copy(a->y);
	bn_mul_mont(ec->mctx, t[2], t[2]);	/* D = y^2 */

	t[3] = bn_new_copy(ec->a);
	bn_mul_mont(ec->mctx, t[3], t[1]);	/* E = a * C */

	t[4] = bn_new_copy(t[3]);
	bn_add_mont(ec->mctx, t[4], t[2]);	/* F = E + D */

	t[5] = bn_new_copy(a->z);
	bn_mul_mont(ec->mctx, t[5], t[5]);	/* H = z^2 */
	bn_add_mont(ec->mctx, t[5], t[5]);	/* 2H */

	t[6] = bn_new_copy(t[4]);
	bn_sub_mont(ec->mctx, t[6], t[5]);	/* J = F - 2H */

	bn_sub_mont(ec->mctx, t[0], t[1]);
	bn_sub_mont(ec->mctx, t[0], t[2]);
	bn_mul_mont(ec->mctx, t[0], t[6]);	/* X3 = (B-C-D) * J */

	bn_sub_mont(ec->mctx, t[3], t[2]);
	bn_mul_mont(ec->mctx, t[3], t[4]);	/* Y3 = (E - D) * F */

	bn_mul_mont(ec->mctx, t[6], t[4]);	/* Z3 = J * F */

	bn_free(a->x);
	bn_free(a->y);
	bn_free(a->z);
	bn_free(t[1]);
	bn_free(t[2]);
	bn_free(t[4]);
	bn_free(t[5]);

	a->x = t[0];
	a->y = t[3];
	a->z = t[6];
}

/*
 * All co-ordinates in projective, Montgomery form. add-2008-bbjlp.
 */
void ece_add(const struct ec_edwards *ec, struct ec_point *a,
	     const struct ec_point *b)
{
	struct bn *t[8];

	assert(ec != EC_INVALID);
	assert(a != EC_POINT_INVALID);
	assert(b != EC_POINT_INVALID);

	t[0] = bn_new_copy(a->z);
	bn_mul_mont(ec->mctx, t[0], b->z);	/* A = Z1 * Z2 */

	t[1] = bn_new_copy(t[0]);
	bn_mul_mont(ec->mctx, t[1], t[1]);	/* B = A^2 */

	t[2] = bn_new_copy(a->x);
	bn_mul_mont(ec->mctx, t[2], b->x);	/* C = X1 * X2 */

	t[3] = bn_new_copy(a->y);
	bn_mul_mont(ec->mctx, t[3], b->y);	/* D = Y1 * Y2 */

	t[4] = bn_new_copy(ec->d);
	bn_mul_mont(ec->mctx, t[4], t[2]);
	bn_mul_mont(ec->mctx, t[4], t[3]);	/* E = d * C * D */

	t[5] = bn_new_copy(t[1]);
	bn_sub_mont(ec->mctx, t[5], t[4]);	/* F = B - E */

	bn_add_mont(ec->mctx, t[1], t[4]);	/* G = B + E */

	t[6] = bn_new_copy(a->x);
	bn_add_mont(ec->mctx, t[6], a->y);	/* X1 + Y1 */
	t[7] = bn_new_copy(b->x);
	bn_add_mont(ec->mctx, t[7], b->y);	/* X2 + Y2 */
	bn_mul_mont(ec->mctx, t[6], t[7]);	/* (X1+Y1)*(X2+Y2) */
	bn_sub_mont(ec->mctx, t[6], t[2]);	/* ... - C */
	bn_sub_mont(ec->mctx, t[6], t[3]);	/* ... - D */
	bn_mul_mont(ec->mctx, t[6], t[5]);	/* ... * F */
	bn_mul_mont(ec->mctx, t[6], t[0]);	/* X3 = ... * A */

	bn_mul_mont(ec->mctx, t[2], ec->a);	/* a * C */
	bn_sub_mont(ec->mctx, t[3], t[2]);	/* D - a * C */
	bn_mul_mont(ec->mctx, t[3], t[1]);	/* ... * G */
	bn_mul_mont(ec->mctx, t[3], t[0]);	/* Y3 = ... * A */

	bn_mul_mont(ec->mctx, t[5], t[1]);	/* Z3 */

	bn_free(a->x);
	bn_free(a->y);
	bn_free(a->z);
	bn_free(t[0]);
	bn_free(t[1]);
	bn_free(t[2]);
	bn_free(t[4]);
	bn_free(t[7]);

	a->x = t[6];
	a->y = t[3];
	a->z = t[5];
}

/* All co-ordinates in projective, Montgomery form. */
void ece_scale(const struct ec_edwards *ec, struct ec_point **_a,
	       const struct bn *b)
{
	int i, msb;
	struct ec_point *pt, *a;

	assert(ec != EC_INVALID);
	assert(!bn_is_zero(b));
	assert(_a != NULL);

	a = *_a;
	if (a == EC_POINT_INVALID)
		a = ece_point_new_copy(ec, &ec->gen);

	pt = ece_point_new_copy(ec, a);
	msb = bn_msb(b);
	assert(msb >= 0);

	for (i = msb - 1; i >= 0; --i) {
		ece_dbl(ec, pt);
		if (bn_test_bit(b, i) == 1)
			ece_add(ec, pt, a);
	}
	ece_point_free(ec, a);
	ece_point_normalize(ec, pt);
	*_a = pt;
}

void ece_free(struct ec_edwards *ec)
{
	if (ec->prime != BN_INVALID)
		bn_free(ec->prime);
	if (ec->a != BN_INVALID)
		bn_free(ec->a);
	if (ec->d != BN_INVALID)
		bn_free(ec->d);
	if (ec->order != BN_INVALID)
		bn_free(ec->order);
	if (ec->gen.x != BN_INVALID)
		bn_free(ec->gen.x);
	if (ec->gen.y != BN_INVALID)
		bn_free(ec->gen.y);
	if (ec->gen.z != BN_INVALID)
		bn_free(ec->gen.z);
	if (ec->mctx)
		bn_ctx_mont_free(ec->mctx);
	free(ec);
}

struct ec_edwards *ec_new_edwards(const struct ec_edwards_params *p)
{
	int i;
	struct ec_edwards *ec;
	struct bn *t[7];

	assert(p != NULL);
	ec = malloc(sizeof(*ec));
	if (ec == NULL)
		goto err0;

	ec->prime = ec->a = ec->d = ec->order = BN_INVALID;
	ec->gen.x = ec->gen.y = ec->gen.z = BN_INVALID;

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

	ec->mctx = bn_ctx_mont_new(t[0]);
	if (ec->mctx == NULL)
		goto err1;

	ec->prime	= t[0];
	ec->a		= t[1];
	ec->d		= t[2];
	ec->gen.x	= t[3];
	ec->gen.y	= t[4];
	ec->gen.z	= t[5];
	ec->order	= t[6];

	bn_to_mont(ec->mctx, ec->a);
	bn_to_mont(ec->mctx, ec->d);
	bn_to_mont(ec->mctx, ec->gen.x);
	bn_to_mont(ec->mctx, ec->gen.y);
	bn_to_mont(ec->mctx, ec->gen.z);
	return ec;
err1:
	for (i = 0; i < 7; ++i)
		if (t[i] != BN_INVALID)
			bn_free(t[i]);
	ece_free(ec);
err0:
	return EC_INVALID;
}




















/* Input y coordinate in little-endian byte-array. */
static struct ec_point *edc_point_decode(const struct edc *edc,
					 const uint8_t *_y)
{
	int lsb;
	struct ec_point *pt;
	struct bn *t[4], *prime, *one, *d, *x[2];
	static uint8_t y[32];

	memcpy(y, _y, 32);
	lsb = 0;
	if (y[31] & 0x80)
		lsb = 1;
	/* Clear the x coordinate bit. */
	y[31] &= 0x7f;

	one = bn_new_from_int(1);
	prime = bn_new_from_string_be(c25519_prime_be, 16);
	d = bn_new_from_string_be(ed25519_d_be, 16);

	t[0] = bn_new_from_bytes_le(y, 32);
	assert(bn_cmp_abs(t[0], prime) < 0);
	t[3] = bn_new_copy(t[0]);

	bn_mul(t[0], t[0]);
	bn_mod(t[0], prime);		/* y^2 */

	t[1] = bn_new_copy(t[0]);
	bn_mul(t[1], d);
	bn_add(t[1], one);
	bn_mod_inv(t[1], prime);

	t[2] = bn_new_copy(t[0]);
	bn_sub(t[2], one);
	bn_mul(t[2], t[1]);
	bn_mod_sqrt(t[2], prime);
	bn_sub(prime, t[2]);

	bn_free(t[0]);
	bn_free(t[1]);
	bn_free(one);
	bn_free(d);

	if (bn_is_even(prime)) {
		x[0] = prime;
		x[1] = t[2];
	} else {
		x[0] = t[2];
		x[1] = prime;
	}
	bn_free(x[!lsb]);
	pt = ece_point_new(edc->ec, x[lsb], t[3]);
	bn_free(x[lsb]);
	bn_free(t[3]);
	return pt;
}

static void edc_point_encode(const struct edc *edc, uint8_t *out,
			     const struct ec_point *pt)
{
	int msb, n;
	uint8_t *bytes;
	struct bn *x, *y;

	x = ece_point_x(edc->ec, pt);
	msb = !bn_is_even(x);
	bn_free(x);

	y = ece_point_y(edc->ec, pt);
	bytes = bn_to_bytes_le(y, &n);
	bn_free(y);

	assert(n <= 32);
	memcpy(out, bytes, n);
	memset(out + n, 0, 32 - n);
	if (msb)
		out[31] |= 0x80;
	free(bytes);
}

struct edc *edc_new_verify(const uint8_t *pub)
{
	struct edc *edc;
	struct ec_edwards_params eep;

	edc = malloc(sizeof(*edc));
	assert(edc);

	eep.prime	= c25519_prime_be;
	eep.order	= c25519_order_be;
	eep.a		= ed25519_a_be;
	eep.d		= ed25519_d_be;
	eep.gx		= ed25519_gx_be;
	eep.gy		= ed25519_gy_be;

	edc->to_sign = 0;
	edc->ec = ec_new_edwards(&eep);

	memcpy(edc->pub, pub, 32);
	edc->pt_pub = edc_point_decode(edc, edc->pub);
	return edc;
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
	ece_scale(edc->ec, &pt, t);
	bn_free(t);

	/* Encode. */
	edc_point_encode(edc, edc->pub, pt);
	edc->pt_pub = pt;
	ece_point_print(edc->ec, pt);
	return edc;
}

void edc_free(struct edc *edc)
{
	assert(edc != EDC_INVALID);
	ece_point_free(edc->ec, edc->pt_pub);
	ece_free(edc->ec);
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
	/* Signing cannot be performed under a verification context. */
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
	ece_scale(edc->ec, &pt, r);
	edc_point_encode(edc, dgst, pt);
	ece_point_free(edc->ec, pt);
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

/* The last 64 bytes of the msg contain the tag. */
void edc_verify(const struct edc *edc, const uint8_t *msg, int mlen)
{
	const uint8_t *r, *s;
	struct bn *ord, *k, *S, *eight;
	struct ec_point *R, *pt[3];
	static struct sha512_ctx ctx;
	static uint8_t dgst[SHA512_DIGEST_LEN];

	assert(edc != EDC_INVALID);
	assert(mlen >= 64);
	/* Verification can be done by a context meant for signing. */
	assert(edc->to_sign == 0 || edc->to_sign == 1);

	ord = bn_new_from_string_be(c25519_order_be, 16);
	eight = bn_new_from_int(8);

	mlen -= 64;
	r = msg + mlen;
	s = r + 32;

	/* R = [r]B */
	R = edc_point_decode(edc, r);
	S = bn_new_from_bytes_le(s, 32);
	assert(bn_cmp_abs(S, ord) < 0);

	sha512_init(&ctx);
	sha512_update(&ctx, r, 32);		/* R */
	sha512_update(&ctx, edc->pub, 32);	/* A */
	sha512_update(&ctx, msg, mlen);		/* M */
	sha512_final(&ctx, dgst);

	/* k == little-endian integer out of dgst. */
	k = bn_new_from_bytes_le(dgst, SHA512_DIGEST_LEN);
	bn_mod(k, ord);

	pt[0] = EC_POINT_INVALID;
	ece_scale(edc->ec, &pt[0], S);
	ece_scale(edc->ec, &pt[0], eight);	/* 8*S*B */

	pt[1] = R;
	ece_scale(edc->ec, &pt[1], eight);

	pt[2] = ece_point_new_copy(edc->ec, edc->pt_pub);
	ece_scale(edc->ec, &pt[2], k);
	ece_scale(edc->ec, &pt[2], eight);

	ece_add(edc->ec, pt[1], pt[2]);
	ece_point_normalize(edc->ec, pt[1]);
	assert(ece_points_equal(edc->ec, pt[0], pt[1]));

	ece_point_free(edc->ec, pt[0]);
	ece_point_free(edc->ec, pt[1]);
	ece_point_free(edc->ec, pt[2]);
	bn_free(S);
	bn_free(eight);
	bn_free(k);
	bn_free(ord);
}
