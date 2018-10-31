/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <string.h>

#include <sha2.h>
#include <hmac.h>
#include <hkdf.h>

void hkdf_sha256_extract(uint8_t *out, const void *salt, int slen,
			 const void *ikm, int klen)
{
	static struct hmac_sha256_ctx hmac;

	assert(out);
	assert(slen >= 0);

	if (salt == NULL || slen == 0) {
		/* prk is assumed to be at least SHA256_DIGEST_LEN sized. */
		slen = SHA256_DIGEST_LEN;
		salt = out;
		memset(out, 0, slen);
	}

	hmac_sha256_init(&hmac, salt, slen);
	hmac_sha256_update(&hmac, ikm, klen);
	hmac_sha256_final(&hmac, out);
}

void hkdf_sha256_expand(uint8_t *out, int olen, const void *prk, int plen,
			const void *info, int ilen)
{
	int n, i;
	uint8_t dgst[SHA256_DIGEST_LEN], cntr;
	static struct hmac_sha256_ctx hmac;

	assert(ilen >= 0);
	assert(olen >= 0);
	assert(plen <= SHA256_DIGEST_LEN);

	for (i = 1; olen; ++i) {
		n = olen < SHA256_DIGEST_LEN ? olen : SHA256_DIGEST_LEN;
		hmac_sha256_init(&hmac, prk, plen);
		if (i > 1)
			hmac_sha256_update(&hmac, dgst, sizeof(dgst));
		if (info && ilen)
			hmac_sha256_update(&hmac, info, ilen);

		/* Store (uint8_t)i into a byte, to avoid endianness issues. */
		cntr = i;
		hmac_sha256_update(&hmac, &cntr, 1);
		hmac_sha256_final(&hmac, dgst);
		memcpy(out, dgst, n);
		out += n;
		olen -= n;
	}
}
