/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _EC_H_
#define _EC_H_

#include <bn.h>

#define EC_INVALID			(struct ec *)NULL
#define EC_POINT_INVALID		(struct ec_point *)NULL

struct ec;
struct ec_point;

/* All strings store numbers in hex. */
struct ec_mont_params {
	const char *prime;
	const char *a;
	const char *b;
	const char *gx;	/* Use projective coordinates with Z = 1. */
	const char *order;	/* Order of the base/gen point. */
};

struct ec	*ec_new_montgomery(const struct ec_mont_params *p);
void		 ec_free(struct ec *ec);

struct ec_point	*ec_gen(const struct ec *ec);
void		 ec_add(const struct ec *ec, struct ec_point *a,
		 const struct ec_point *b);
void		 ec_mul(const struct ec *ec, struct ec_point *a,
		 const struct bn *d);

struct ec_point	*ec_gen_keys(const struct ec *ec, struct bn **priv);
#endif
