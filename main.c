/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>

#include <bn.h>
#include <ec.h>

int main()
{
	struct ec *ec;
	struct bn *priv;
	struct ec_point *pub;
	struct ec_mont_params emp;

	emp.prime ="7fffffffffffffff ffffffffffffffff ffffffffffffffff"
		"ffffffffffffffed";
	emp.a = "76d06";	/* hex(486662). */
	emp.b = "1";
	emp.gx = "9";
	emp.order = "1000000000000000 0000000000000000 14def9dea2f79cd6"
		"5812631a5cf5d3ed";

	/* Test. */
	ec = ec_new_montgomery(&emp);
	priv = BN_INVALID;
	pub = ec_gen_pair(ec, &priv);
	ec_point_free(ec, pub);
	bn_free(priv);
	ec_free(ec);

	return 0;
}
