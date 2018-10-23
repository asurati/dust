/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sha2.h>
#include <hmac.h>
#include <hkdf.h>

static struct hmac_sha256_ctx hmac;

void hkdf_sha256_extract(const void *salt, int slen, const void *ikm, int klen,
			 uint8_t *prk)
{
	uint8_t buf[SHA256_DIGEST_LEN];

	assert(slen >= 0);

	if (salt == NULL || slen == 0) {
		memset(buf, 0, sizeof(buf));
		salt = buf;
		slen = SHA256_DIGEST_LEN;
	}

	hmac_sha256_init(&hmac, salt, slen);
	hmac_sha256_update(&hmac, ikm, klen);
	hmac_sha256_final(&hmac, prk);
}

void hkdf_sha256_expand(const void *prk, int plen, const void *info, int ilen,
			uint8_t *out, int olen)
{
	int n, i;
	uint8_t dgst[SHA256_DIGEST_LEN];

	assert(ilen >= 0);
	assert(olen >= 0);
	assert(plen <= SHA256_DIGEST_LEN);

	for (i = 1; olen; ++i) {
		n = olen <= SHA256_DIGEST_LEN ? olen : SHA256_DIGEST_LEN;
		hmac_sha256_init(&hmac, prk, plen);
		if (i > 1)
			hmac_sha256_update(&hmac, dgst, sizeof(dgst));
		if (info && ilen)
			hmac_sha256_update(&hmac, info, ilen);
		hmac_sha256_update(&hmac, &i, 1);
		hmac_sha256_final(&hmac, dgst);
		memcpy(out, dgst, n);
		out += n;
		olen -= n;
	}
}
