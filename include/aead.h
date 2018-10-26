/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _AEAD_H_
#define _AEAD_H_

/* All nums at the interfaces, in little-endian byte-array form. */
void	aead_enc(const uint8_t* key, const uint8_t *nonce, const void *msg,
	int mlen,  const void *aad, int alen, uint8_t *out);
void	aead_dec(const uint8_t* key, const uint8_t *nonce, const void *msg,
	int mlen,  const void *aad, int alen, uint8_t *out);
#endif
