/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _HKDF_H_
#define _HKDF_H_

#include <stdint.h>

void	hkdf_sha256_extract(const void *salt, int slen, const void *ikm,
	int klen, uint8_t *prk);

/* Returns in big-endian form; can be directly used to instantiate bn. */
void	hkdf_sha256_expand(const void *prk, int plen, const void *info,
	int ilen, uint8_t *out, int olen);
#endif
