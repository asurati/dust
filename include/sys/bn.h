/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_BN_H_
#define _SYS_BN_H_

#include <bn.h>
#include <sys/limb.h>

struct bn {
	int nalloc;	/* # of allocated limbs. */
	int nsig;	/* # of signitficant limbs. */
	int neg;
	limb_t *l;
};
#endif
