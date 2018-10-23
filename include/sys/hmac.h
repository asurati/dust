/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_HMAC_H_
#define _SYS_HMAC_H_

#include <sha2.h>
#include <hmac.h>

struct hmac_sha256 {
	struct sha256_ctx sha256;	/* B=64, L=32 */
	uint8_t k[SHA256_BLOCK_LEN];
};
#endif
