/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>

#include <bn.h>
#include <rndm.h>
#include <ec.h>

// 3y^2=x^3 + 5x^2 + x mod 65537
// (3,5) on the curve.

// y^2=x^3 + 5x^2 + x mod eaad
// (4,0x94) on the curve

struct bn *bn_rand(const struct bn *m)
{
	int nbits, nbytes;
	uint8_t *bytes;
	struct bn *t;

	nbits = bn_msb(m) + 1;
	nbytes = (nbits + 7) >> 3;
	bytes = malloc(nbytes);
	assert(bytes);

	/* TODO more efficient way? */
	for (;;) {
		rndm_fill(bytes, nbits);
		t = bn_new_from_bytes(bytes, nbytes);
		/* TODO check for zero. */
		if (bn_cmp_abs(t, m) < 0)
			break;
		bn_free(t);
	}
	return t;
}

int main()
{
	struct ec *ec;
	struct bn *priv[2], *prime;
	struct ec_point *pub[2];
	struct ec_mont_params emp;

	/* Must be the first call. */
	bn_init();

	emp.c4 = NULL;
	emp.prime = "7fffffffffffffff ffffffffffffffff ffffffffffffffff"
		"ffffffffffffffed";
	emp.a = "76d06";	// hex(486662)
	emp.b = "1";
	emp.gx = "9";
	emp.order = "1000000000000000 0000000000000000 14def9dea2f79cd6"
		"5812631a5cf5d3ed";

	prime = bn_new_from_string(emp.prime, 16);

	/* Test. */
	ec = ec_new_montgomery(&emp);
	priv[0] = bn_rand(prime);
	priv[1] = bn_rand(prime);

	pub[0] = ec_gen_public(ec, priv[0]);
	bn_print("priv0:", priv[0]);
	ec_point_print(ec, pub[0]);

	pub[1] = ec_gen_public(ec, priv[1]);
	bn_print("priv1:", priv[1]);
	ec_point_print(ec, pub[1]);

	printf("----------\n");

	ec_scale(ec, pub[0], priv[1]);
	ec_scale(ec, pub[1], priv[0]);

	ec_point_print(ec, pub[0]);
	ec_point_print(ec, pub[1]);

	ec_point_free(ec, pub[0]);
	ec_point_free(ec, pub[1]);
	bn_free(priv[0]);
	bn_free(priv[1]);
	bn_free(prime);
	ec_free(ec);
	bn_fini();
	return 0;
}
