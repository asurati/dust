/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>

#include <sys/ec.h>

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
	if (ecm->gen.x != BN_INVALID)
		bn_free(ecm->gen.x);
	if (ecm->gen.z != BN_INVALID)
		bn_free(ecm->gen.z);

	/* ecm freed by the wrapper. */
}

static struct ec *ec_mont_new(const struct ec_mont_params *p)
{
	struct ec *ec;
	struct ec_mont *ecm;

	assert(p != NULL);
	ec = malloc(sizeof(*ec));
	if (ec == NULL)
		goto err0;

	ec->form = ECF_MONTGOMERY;
	ecm = &ec->u.mont;

	ecm->prime = ecm->a = ecm->b = ecm->order = BN_INVALID;
	ecm->gen.x = ecm->gen.y = ecm->gen.z = BN_INVALID;

	ecm->prime	= bn_new_from_string(p->prime, 16);
	ecm->a		= bn_new_from_string(p->a, 16);
	ecm->b		= bn_new_from_string(p->b, 16);
	ecm->order	= bn_new_from_string(p->order, 16);
	ecm->gen.x	= bn_new_from_string(p->gx, 16);
	ecm->gen.z	= bn_new_from_string("1", 16);

	if (ecm->prime == BN_INVALID || ecm->a == BN_INVALID ||
	    ecm->b == BN_INVALID || ecm->order == BN_INVALID ||
	    ecm->gen.x == BN_INVALID || ecm->gen.z == BN_INVALID)
		goto err1;

	return ec;
err1:
	ec_mont_free(ecm);
	free(ec);
err0:
	return EC_INVALID;
}

static void ec_mont_add(const struct ec_mont *ecm, struct ec_point *a,
			const struct ec_point *b)
{
	(void)ecm;
	(void)a;
	(void)b;


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

void ec_add(const struct ec *ec, struct ec_point *a, const struct ec_point *b)
{
	assert(ec != EC_INVALID);

	switch (ec->form) {
	case ECF_MONTGOMERY:
		ec_mont_add(&ec->u.mont, a, b);
		break;
	default:
		assert(0);
	}
}

