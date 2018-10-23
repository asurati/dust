/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SHA2_H_
#define _SHA2_H_

#include <stdint.h>

struct sha256_ctx {
	uint8_t res[104];
};

void	sha256_init(struct sha256_ctx *ctx);
void	sha256_update(struct sha256_ctx *ctx, const void *bytes, int len);

/* Returns in big-endian form; can be directly used to instantiate bn. */
void	sha256_final(struct sha256_ctx *ctx, uint8_t *bytes);
#endif
