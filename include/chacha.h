/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _CHACHA_H_
#define _CHACHA_H_

#include <stdint.h>

struct chacha20_ctx {
	uint8_t res[132];
};

/* All numbers at the interfaces in big-endian byte-array form. */
void	chacha20_init(struct chacha20_ctx *ctx, const void *key, int len,
	const void *nonce);
void	chacha20_enc(struct chacha20_ctx *ctx, const void *in, void *out,
	int len);
void	chacha20_dec(struct chacha20_ctx *ctx, const void *in, void *out,
	int len);
#endif
