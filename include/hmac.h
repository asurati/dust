/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _HMAC_H_
#define _HMAC_H_

#include <stdint.h>

struct hmac_sha256_ctx {
	uint8_t res[168];
};

void	hmac_sha256_init(struct hmac_sha256_ctx *ctx, const uint8_t *key,
	int klen);
void	hmac_sha256_update(struct hmac_sha256_ctx *ctx, const void *bytes,
	int len);

/* Returns in big-endian form; can be directly used to instantiate bn. */
void	hmac_sha256_final(struct hmac_sha256_ctx *ctx, uint8_t *bytes);
#endif
