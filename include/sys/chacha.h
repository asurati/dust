/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_CHACHA_H_
#define _SYS_CHACHA_H_

#include <chacha.h>

struct chacha20  {
	uint32_t state[16];
	uint32_t stream[16];
	int ix;
};
#endif
