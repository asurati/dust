/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SHA2_H_
#define _SHA2_H_

#include <stdint.h>

#define SHA256_BLOCK_LEN			64
#define SHA256_DIGEST_LEN			32
#define SHA512_BLOCK_LEN			128
#define SHA512_DIGEST_LEN			64

struct sha256_ctx {
	uint8_t res[104];
};

struct sha512_ctx {
	uint8_t res[200];
};

void	sha256_init(struct sha256_ctx *ctx);
void	sha256_update(struct sha256_ctx *ctx, const void *bytes, int len);
/* Returns in big-endian form. */
void	sha256_final(struct sha256_ctx *ctx, uint8_t *bytes);

void	sha512_init(struct sha512_ctx *ctx);
void	sha512_update(struct sha512_ctx *ctx, const void *bytes, int len);
/* Returns in big-endian form. */
void	sha512_final(struct sha512_ctx *ctx, uint8_t *bytes);
#endif
