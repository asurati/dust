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
	if (ecm->mctx)
		bn_ctx_mont_free(ecm->mctx);

	/* ecm freed by the wrapper. */
}

static struct ec *ec_mont_new(const struct ec_mont_params *p)
{
	int i;
	struct ec *ec;
	struct ec_mont *ecm;
	struct bn *t[6];

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

	for (i = 0; i < 6; ++i)
		if (t[i] == BN_INVALID)
			goto err1;

	ecm->mctx = bn_ctx_mont_new(t[0]);
	if (ecm->mctx == NULL)
		goto err1;

	ecm->prime	= t[0];
	ecm->a		= t[1];
	ecm->b		= t[2];
	ecm->gen.x	= t[3];
	ecm->gen.z	= t[4];
	ecm->order	= t[5];

	bn_to_mont(ecm->mctx, ecm->a);
	bn_to_mont(ecm->mctx, ecm->b);
	bn_to_mont(ecm->mctx, ecm->gen.x);
	bn_to_mont(ecm->mctx, ecm->gen.z);
	return ec;
err1:
	for (i = 0; i < 6; ++i)
		if (t[i] != BN_INVALID)
			bn_free(t[i]);
	ec_mont_free(ecm);
	free(ec);
err0:
	return EC_INVALID;
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
