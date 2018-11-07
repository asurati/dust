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
#include <poly1305.h>
#include <aead.h>

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
		t = bn_new_from_bytes_be(bytes, nbytes);
		/* TODO check for zero. */
		if (bn_cmp_abs(t, m) < 0)
			break;
		bn_free(t);
	}
	return t;
}

const uint8_t priv[32] = {
	0x6a,0x34,0x8c,0x51,0x6a,0x1b,0xc1,0x77,0x18,0xfc,0x57,0x66,0x2e,0xb0,
	0xa7,0xc0,0xbc,0xfe,0xdd,0x94,0xdf,0x80,0xb1,0x1e,0x6b,0xa5,0x99,0x58,
	0x59,0xf0,0xe6,0x10
};

const char *priv_str = "9d61b19deffd5a60ba844af492ec2cc4"
"4449c5697b326919703bac031cae7f60";

int main()
{
	struct edc *edc;
	struct bn *t;
	uint8_t *bytes;
	int n;
	uint8_t tag[64];

	bn_init();
	t = bn_new_from_string_be(priv_str, 16);
	bytes = bn_to_bytes_be(t, &n);
	assert(n == 32);
	bn_free(t);

	edc = edc_new_sign(bytes);
	edc_sign(edc, tag, NULL, 0);
	for (int i = 0; i < 64; ++i)
		printf("%02x", tag[i]);
	printf("\n");
	edc_free(edc);
	free(bytes);
	bn_fini();
	return 0;
	(void)tag;
}

#if 0
int main()
{
	struct tls_ctx *ctx;
	bn_init();
	ctx = tls_ctx_new();
	tls_client_machine(ctx, "127.0.0.1", 8443);
	bn_fini();
	return 0;
}
#endif
