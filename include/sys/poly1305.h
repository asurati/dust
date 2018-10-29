/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_POLY1305_H_
#define _SYS_POLY1305_H_

#include <bn.h>
#include <poly1305.h>

struct poly1305 {
	struct bn *prime;
	struct bn *acc;
	struct bn *r;
	struct bn *s;
	uint8_t buf[16];
	int ix;
};
#endif
