/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _EC_H_
#define _EC_H_

#include <bn.h>

extern const char *c25519_prime_be;
extern const char *c25519_a_be;
extern const char *c25519_b_be;
extern const char *c25519_gx_be;
extern const char *c25519_order_be;

extern const char *ed25519_a_be;
extern const char *ed25519_d_be;
extern const char *ed25519_gx_be;
extern const char *ed25519_gy_be;

#define EC_INVALID			(struct ec *)NULL
#define EC_POINT_INVALID		(struct ec_point *)NULL

struct ec;
struct ec_point;

/* All strings store numbers in hex in big-endian form. */
struct ec_mont_params {
	const char *prime;
	const char *a;
	const char *b;
	const char *gx;	/* Use projective coordinates with Z = 1. */
	const char *order;	/* Order of the base/gen point. */
};

struct ec_edwards_params {
	const char *prime;
	const char *a;	/* a != 1 => twisted curve. */
	const char *d;
	const char *gx;
	const char *gy;	/* Projective coordinates with Z = 1. */
	const char *order;	/* Order of the base/gen point. */
};

struct ec	*ec_new_montgomery(const struct ec_mont_params *p);
struct ec	*ec_new_edwards(const struct ec_edwards_params *p);
void		 ec_free(struct ec *ec);

struct ec_point	*ec_point_new(const struct ec *ec, const struct bn *x,
		 const struct bn *y, const struct bn *z);
struct ec_point	*ec_point_new_copy(const struct ec *ec,
		 const struct ec_point *a);
void		 ec_point_free(const struct ec *ec, struct ec_point *a);
void		 ec_point_print(const struct ec *ec, const struct ec_point *a);
struct bn	*ec_point_x(const struct ec *ec, const struct ec_point *a);
struct bn	*ec_point_y(const struct ec *ec, const struct ec_point *a);

void		 ec_scale(const struct ec *ec, struct ec_point **a,
		 const struct bn *b);


/* edc is the context for ed25519. */
struct edc;

#define EDC_INVALID			(struct edc *)NULL

/*
 * private key is a byte-array, with no specific structure, not even
 * numeric. Length assumed to be 32 bytes.
 */

struct edc	*edc_new_sign(const uint8_t *priv);
struct edc	*edc_new_verify(const uint8_t *pub);
void		 edc_free(struct edc *edc);
void		 edc_sign(const struct edc *edc, uint8_t *tag,
		 const uint8_t *msg, int mlen);
#endif
