/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_BN_H_
#define _SYS_BN_H_

#include <bn.h>
#include <sys/limb.h>

/*
 * TODO Define APIs to accept a struct bn representing a modulus M which
 * is to be used to restrict the results of the operations to mod M.
 */
struct bn {
	int nalloc;	/* # of allocated limbs. */
	int nsig;	/* # of signitficant limbs. */
	int neg;
	limb_t *l;
};

struct bn_ctx_mont {
	int msb;		/* MSSB in m. */
	struct bn *m;		/* Modulus. Odd and >= 3. */
	struct bn *r;		/* Reducer. */
	struct bn *rinv;	/* r' = Reducer's Inverse Mod m. */
	struct bn *mask;	/* Modulo R operation (AND). */
	struct bn *factor;	/* = (rr' - 1) / m. */
	struct bn *one;		/* 1 in Montgomery form for the given m. */
};
#endif
