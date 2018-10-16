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
	struct ec_mont_params emp;

	emp.prime ="7fffffffffffffff ffffffffffffffff ffffffffffffffff"
		"ffffffffffffffed";
	emp.a = "76d06";	/* hex(486662). */
	emp.b = "1";
	emp.gx = "9";
	emp.order = "1000000000000000 0000000000000000 14def9dea2f79cd6"
		"5812631a5cf5d3ed";

	ec = ec_new_montgomery(&emp);
	ec_free(ec);
}

#if 0
const char *prime =
"FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF";
const char *coeff_a =
"FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC";
const char *coeff_b =
"5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B";
const char *gen_x =
"6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296";
const char *gen_y =
"4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5";

int main()
{
	struct bn *p, *ca, *cb, *gx, *gy, *t;
	p  = bn_new_from_string(prime, 16);
	ca = bn_new_from_string(coeff_a, 16);
	cb = bn_new_from_string(coeff_b, 16);
	gx = bn_new_from_string(gen_x, 16);
	gy = bn_new_from_string(gen_y, 16);

	t = bn_new_from_string("2", 16);
	bn_mod_pow(gy, t, p);	/* y^2 mod p */
	bn_free(t);

	bn_mul(ca, gx);	/* ax. */
	bn_add(ca, cb);	/* ax + b. */

	t = bn_new_from_string("3", 16);
	bn_mod_pow(gx, t, p);	/* x^3 mod p */
	bn_free(t);

	bn_add(gx, ca);	/* x^3 + ax + b. */
	bn_mod(gx, p);	/* (x^3 + ax + b) mod p. */

	bn_sub(gy, gx);	/* (y^2 - (x^3 + ax + b)) mod p. */
	bn_print("E(gx,gy): ", gy);

	bn_free(p);
	bn_free(ca);
	bn_free(cb);
	bn_free(gx);
	bn_free(gy);
	return 0;
}
#endif
