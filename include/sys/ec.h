/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_EC_H_
#define _SYS_EC_H_

#include <ec.h>

struct ec_point {
	struct bn *x;
	struct bn *y;
	struct bn *z;
};

struct ec_mont {
	struct bn *prime;
	struct bn *a;
	struct bn *b;
	struct bn *order;
	struct bn *cnst;	/* (a + 2) / 4 */
	struct ec_point gen;
	struct bn_ctx_mont *mctx;
};

struct ec_edwards {
	struct bn *prime;
	struct bn *a;
	struct bn *d;
	struct bn *order;
	struct ec_point gen;
	struct bn_ctx_mont *mctx;
};

struct edc {
	struct ec_edwards *ec;
	struct ec_point *pt_pub;
	uint8_t priv_dgst[SHA512_DIGEST_LEN];	/* H(priv). */
	uint8_t pub[32];
	char to_sign;
};
#endif
