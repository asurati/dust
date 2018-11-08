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

int main()
{
	return 0;
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
