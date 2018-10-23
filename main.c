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

// 3y^2=x^3 + 5x^2 + x mod 65537
// (3,5) on the curve.

// y^2=x^3 + 5x^2 + x mod eaad
// (4,0x94) on the curve

/* Curve25519 parameters. */
const char *c25519_prime	=
"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed";
const char *c25519_a		= "76d06";	// hex(486662)
const char *c25519_b		= "1";
const char *c25519_gx		= "9";
const char *c25519_order	=
"1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed";

const char *priv_str	=
"59effe2eb776d8e7118dda26b46cce413bfa0e2d4993acabaae91cf16c8c7d28";
const char *pub_str	=
"671e3b404cd8512b5077822a2e7764d614cdda6f67d3c6433ce63d5bcb132b7d";

struct bn *bn_rand(const struct bn *m)
{
	int nbits, nbytes;
	uint8_t *bytes;
	struct bn *t;

	t = bn_new_from_string(priv_str, 16);
	return t;

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


uint8_t buf[4096];
int main()
{
	int sock, n;
	struct bn *t;
	uint8_t *bytes;
	struct sockaddr_in srvr = {0};
	struct ec *ec;
	struct bn *priv[2];
	struct ec_point *pub[2];
	struct ec_mont_params emp;

	n = 0;

	bn_init();
	bytes = malloc(32);
	goto parse;

	t = bn_new_from_string(pub_str, 16);
	bytes = bn_to_bytes_le(t, &n);
	bn_free(t);

	assert(n == 32);
	n = tls_fill_chello(buf, 4096, bytes);
	printf("chello %d\n", n);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	srvr.sin_family = AF_INET;
	srvr.sin_port = htons(443);
	inet_pton(AF_INET, "127.0.0.1", &srvr.sin_addr);
	connect(sock, (const struct sockaddr *)&srvr, sizeof(srvr));
	send(sock, buf, n, 0);
	n = recv(sock, buf, 4096, 0);
	printf("recvd %d\n", n);
	close(sock);
parse:
	n = tls_parse_records(buf, 0, bytes);

	emp.prime = c25519_prime;
	emp.a = c25519_a;
	emp.b = c25519_b;
	emp.gx = c25519_gx;
	emp.order = c25519_order;
	ec = ec_new_montgomery(&emp);

	t = bn_new_from_bytes(bytes, 32);
	bn_print("", t);
	priv[0] = bn_new_from_string(priv_str, 16);	//my private key
	pub[1] = ec_point_new(ec, t, NULL, NULL);	//their public key

	ec_scale(ec, pub[1], priv[0]);	//shared secret.
	ec_point_print(ec, pub[1]);

	ec_point_free(ec, pub[1]);
	ec_free(ec);
	bn_free(priv[0]);
	bn_free(t);
	free(bytes);
	bn_fini();
	sleep(60000);
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
