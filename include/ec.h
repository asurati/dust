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

struct ec_point	*ec_point_new_copy(const struct ec *ec,
		 const struct ec_point *a);
void		 ec_point_free(const struct ec *ec, struct ec_point *a);
void		 ec_point_print(const struct ec *ec, const struct ec_point *a);
void		 ec_point_normalize(const struct ec *ec, struct ec_point *a);

void		 ec_scale(const struct ec *ec, struct ec_point *a,
		 const struct bn *b);
struct ec_point	*ec_gen_pair(const struct ec *ec, struct bn **priv);
void		 ec_gen_shared(const struct ec *ec, const struct bn *priv,
		 struct ec_point *pub);
#endif
