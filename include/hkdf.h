/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _HKDF_H_
#define _HKDF_H_

#include <stdint.h>

void	hkdf_sha256_extract(uint8_t *out, const void *salt, int slen,
	const void *ikm, int klen);

/* Returns in big-endian form; can be directly used to instantiate bn. */
void	hkdf_sha256_expand(uint8_t *out, int olen, const void *prk, int plen,
	const void *info, int ilen);
#endif
