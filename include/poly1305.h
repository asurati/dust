/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _POLY1305_H_
#define _POLY1305_H_

#include <stdint.h>

struct poly1305_ctx {
	uint8_t res[56];
};

/* All nums at the interfaces, in little-endian byte-array form. */

/*
 * key and out have no inherent structure; hence they'll always be an array.
 * The msg may have a structure. To ease passing it to the function, keep
 * the argument void *.
 */
void	poly1305_init(struct poly1305_ctx *ctx, const uint8_t *key);
void	poly1305_update(struct poly1305_ctx *ctx, const void *bytes, int len);
void	poly1305_final(struct poly1305_ctx *ctx, uint8_t *out);
#endif
