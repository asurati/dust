/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_SHA2_H_
#define _SYS_SHA2_H_

#include <sha2.h>

struct sha256 {
	uint32_t h[8];
	/* XXX nwords restricts the total size of data that can be hashed. */
	uint32_t nwords;	/* # of 512-bit words. */
	uint8_t buf[SHA256_BLOCK_LEN];	/* Accumulator */
	uint8_t nbytes;		/* # of bytes in the accumulator. */
	uint8_t res[3];
};

struct sha512 {
	uint64_t h[8];
	/* XXX nwords restricts the total size of data that can be hashed. */
	uint32_t nwords;	/* # of 1024-bit words. */
	uint8_t buf[SHA512_BLOCK_LEN];	/* Accumulator */
	uint8_t nbytes;		/* # of bytes in the accumulator. */
	uint8_t res[3];
};
#endif
