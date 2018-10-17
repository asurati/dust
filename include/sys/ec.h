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

enum ec_form {
	ECF_WEIERSTRASS,
	ECF_MONTGOMERY,
	ECF_EDWARDS,
	ECF_MAX,
};

struct ec_mont {
	struct bn *prime;
	struct bn *a;
	struct bn *b;
	struct bn *order;
	struct ec_point gen;
};

struct ec {
	enum ec_form form;
	union {
		struct ec_mont mont;
	} u;
};
#endif