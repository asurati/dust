/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>

#include <bn.h>
#include <ec.h>

/*
[u0@arch ~]$ openssl genpkey -algorithm x25519 -text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIKinutjKrDOqgs3HCaO6Tf3eAIkNWB2v87M75o+VXhxg
-----END PRIVATE KEY-----
X25519 Private-Key:
priv:
    a8:a7:ba:d8:ca:ac:33:aa:82:cd:c7:09:a3:ba:4d:
    fd:de:00:89:0d:58:1d:af:f3:b3:3b:e6:8f:95:5e:
    1c:60
pub:
    0c:8e:b1:04:fe:d8:76:2b:81:7c:98:17:42:60:11:
    b6:16:5f:fd:7e:c4:8c:49:5b:6e:c3:c5:2c:71:e0:
    0e:3c
*/
int main()
{
	struct ec *ec;
	struct bn *priv[2];
	struct ec_point *pub[2];
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
	priv[0] = BN_INVALID;
	priv[1] = BN_INVALID;

	pub[0] = ec_gen_pair(ec, &priv[0]);
	bn_print("priv:", priv[0]);
	ec_point_print(ec, pub[0]);
	ec_point_normalize(ec, pub[0]);
	ec_point_print(ec, pub[0]);
	exit(0);

	pub[1] = ec_gen_pair(ec, &priv[1]);

	ec_scale(ec, pub[1], priv[0]);
	ec_scale(ec, pub[0], priv[1]);

	ec_point_print(ec, pub[0]);
	ec_point_print(ec, pub[1]);

	ec_point_free(ec, pub[0]);
	ec_point_free(ec, pub[1]);
	bn_free(priv[0]);
	bn_free(priv[1]);
	ec_free(ec);

	return 0;
}
