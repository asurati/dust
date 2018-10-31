/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <string.h>
#include <endian.h>	/* Non-standard. */

#include <chacha.h>
#include <poly1305.h>
#include <aead.h>

/* Conforms to RFC 7539 and 7905. */

static void aead_mac(uint8_t *out, const uint8_t* otk, const void *msg,
		     int mlen, const void *aad, int alen)
{
	int pad;
	struct poly1305_ctx ctx;
	static const uint8_t z[16] = {0};
	uint64_t v;

	poly1305_init(&ctx, otk);
	poly1305_update(&ctx, aad, alen);
	pad = 16 - (alen & 0xf);
	if (pad != 16)
		poly1305_update(&ctx, z, pad);
	poly1305_update(&ctx, msg, mlen);
	pad = 16 - (mlen & 0xf);
	if (pad != 16)
		poly1305_update(&ctx, z, pad);
	v = htole64(alen);
	poly1305_update(&ctx, &v, sizeof(v));
	v = htole64(mlen);
	poly1305_update(&ctx, &v, sizeof(v));
	poly1305_final(&ctx, out);
}

/* The last 16 bytes of the msg are the tag. */
int aead_dec(const uint8_t* key, const uint8_t *nonce, const void *msg,
	     int mlen,  const void *aad, int alen, uint8_t *out)
{
	struct chacha20_ctx ctx;
	static uint8_t otk[32];

	assert(key);
	assert(nonce);
	assert(msg);
	assert(mlen > 16);
	assert(aad);
	assert(out);

	/* Generate the one time key for mac. */
	memset(otk, 0, sizeof(otk));
	chacha20_init(&ctx, key, nonce, 0);
	chacha20_enc(&ctx, otk, otk, 32);

	/* Generate mac. */
	aead_mac(otk, otk, msg, mlen - 16, aad, alen);

	/* Not-a-constant-time compare. */
	assert(memcmp(otk, (const uint8_t *)msg + mlen - 16, 16) == 0);

	/* Decrypt the data. */
	chacha20_init(&ctx, key, nonce, 1);
	chacha20_dec(&ctx, out, msg, mlen - 16);
	return mlen - 16;
}

int aead_enc(const uint8_t* key, const uint8_t *nonce, const void *msg,
	     int mlen,  const void *aad, int alen, uint8_t *out)
{
	struct chacha20_ctx ctx;
	static uint8_t otk[32];

	assert(key);
	assert(nonce);
	assert(msg);
	assert(mlen > 0);
	assert(aad);
	assert(out);

	/* Generate the one time key for mac. */
	memset(otk, 0, sizeof(otk));
	chacha20_init(&ctx, key, nonce, 0);
	chacha20_enc(&ctx, otk, otk, 32);

	/* Encrypt the data. */
	chacha20_init(&ctx, key, nonce, 1);
	chacha20_enc(&ctx, out, msg, mlen);

	/* Generate mac. */
	aead_mac(out + mlen, otk, out, mlen, aad, alen);
	return mlen + 16;
}
