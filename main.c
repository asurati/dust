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

// 3y^2=x^3 + 5x^2 + x mod 65537
// (3,5) on the curve.

// y^2=x^3 + 5x^2 + x mod eaad
// (4,0x94) on the curve

/* Curve25519 parameters. */

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

uint8_t shared[] = {
	0x61,0x33,0xe7,0x2b,0xb7,0xea,0xd5,0xfb,0x53,0x09,0x2c,0x07,0x71,0xfb,
	0x21,0xdf,0x3d,0x2a,0x46,0xb5,0x0a,0x07,0xe7,0x0b,0x5f,0x2a,0x8d,0xc9,
	0x97,0x2e,0xf9,0x5b,
};

uint8_t shts[] = {
	0xf2,0x0d,0x23,0xfa,0x9c,0x25,0xdd,0x8a,0xda,0x38,0x16,0xa3,0xa4,0x1f,
	0xb1,0x4c,0x52,0xf7,0xd3,0xae,0x9a,0xbd,0x6b,0x8b,0x3c,0x34,0x04,0x76,
	0x02,0xf9,0xae,0xd9,
};

uint8_t shts_key[] = {
	0xab,0x1e,0x63,0x1d,0xb3,0xc6,0x45,0x56,0x3d,0xe5,0xe2,0xcd,0xa0,0x7d,
	0x60,0x0c,0xd0,0xf2,0x0c,0x8b,0x17,0x63,0xe8,0x75,0xad,0x8c,0x2b,0xad,
	0x82,0xfe,0xd7,0xab,
};

uint8_t shts_iv[] = {
	0x28,0x65,0x6b,0xbd,0xa8,0x4e,0x72,0x8f,
};
uint8_t buf[4096];
int main()
{
	struct tls_ctx *tlsc;

	bn_init();
	tlsc = tls_ctx_new();
	tls_connect(tlsc, "127.0.0.1", 443);
	bn_fini();
	return 0;
}

#if 0
/*
 * The numbers given below in the vector are in little endian format.
 * To use them with the bn API, they must first be converted to
 * bigendian.

   Test vector:

   Alice's private key, a:
     77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
   Alice's public key, X25519(a, 9):
     8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
   Bob's private key, b:
     5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
   Bob's public key, X25519(b, 9):
     de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
   Their shared secret, K:
     4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
*/

const char *priv_alice =
//"2a2cb91da5fb77b12a99c0eb872f4cdf4566b25172c1163c7da518730a6d0777";
"6a2cb91da5fb77b12a99c0eb872f4cdf4566b25172c1163c7da518730a6d0770";
const char *priv_bob =
//"ebe088ff278b2f1cfdb6182629b13b6fe60e80838b7fe1794b8a4a627e08ab5d";
"6be088ff278b2f1cfdb6182629b13b6fe60e80838b7fe1794b8a4a627e08ab58";

int main()
{
	struct ec *ec;
	struct bn *priv[2], *prime;
	struct ec_point *pub[2];
	struct ec_mont_params emp;

	bn_init();

	emp.prime = c25519_prime;
	emp.a = c25519_a;
	emp.b = c25519_b;
	emp.gx = c25519_gx;
	emp.order = c25519_order;
	prime = bn_new_from_string(emp.prime, 16);

	/* Test. */
	ec = ec_new_montgomery(&emp);
//	priv[0] = bn_rand(prime);
//	priv[1] = bn_rand(prime);
	priv[0] = bn_new_from_string(priv_alice, 16);
	priv[1] = bn_new_from_string(priv_bob, 16);

	pub[0] = ec_gen_public(ec, priv[0]);
	bn_print("priv_alice:\n  ", priv[0]);
	printf("pub_alice:\n");
	ec_point_print(ec, pub[0]);

	pub[1] = ec_gen_public(ec, priv[1]);
	bn_print("priv_bob:\n  ", priv[1]);
	printf("pub_bob:\n");
	ec_point_print(ec, pub[1]);

	printf("shared_alice:\n");
	ec_scale(ec, pub[1], priv[0]);
	ec_point_print(ec, pub[1]);

	printf("shared_bob:\n");
	ec_scale(ec, pub[0], priv[1]);
	ec_point_print(ec, pub[0]);

	ec_point_free(ec, pub[0]);
	ec_point_free(ec, pub[1]);
	bn_free(priv[0]);
	bn_free(priv[1]);
	bn_free(prime);
	ec_free(ec);
	bn_fini();
	return 0;
}
#endif
