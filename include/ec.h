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

#define EC_INVALID			(void *)NULL
#define EC_POINT_INVALID		(struct ec_point *)NULL

struct ec_mont;
struct ec_edwards;
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

struct ec_mont	*ec_new_montgomery(const struct ec_mont_params *p);
void		 ecm_free(struct ec_mont *ec);
struct ec_point	*ecm_point_new(const struct ec_mont *ec, const struct bn *x);
struct ec_point	*ecm_point_new_copy(const struct ec_mont *ec,
		 const struct ec_point *a);
void		 ecm_point_print(const struct ec_mont *ec,
		 const struct ec_point *a);
struct bn	*ecm_point_x(const struct ec_mont *ec,
		 const struct ec_point *a);
void		 ecm_point_free(const struct ec_mont *ec, struct ec_point *a);
void		 ecm_point_normalize(const struct ec_mont *ec,
		 struct ec_point *a);
void		 ecm_scale(const struct ec_mont *ec, struct ec_point **a,
		 const struct bn *b);
void		 ecm_dbl(const struct ec_mont *ec, struct ec_point *a);
void		 ecm_diffadd(const struct ec_mont *ec, struct ec_point *diff,
		 const struct ec_point *b, const struct ec_point *c);
struct ec_edwards
		*ec_new_edwards(const struct ec_edwards_params *p);
void		 ece_free(struct ec_edwards *ec);
struct ec_point	*ece_point_new(const struct ec_edwards *ec,
		 const struct bn *x, const struct bn *y);
struct ec_point	*ece_point_new_copy(const struct ec_edwards *ec,
		 const struct ec_point *a);
void		 ece_point_print(const struct ec_edwards *ec,
		 const struct ec_point *a);
struct bn	*ece_point_x(const struct ec_edwards *ec,
		 const struct ec_point *a);
struct bn	*ece_point_y(const struct ec_edwards *ec,
		 const struct ec_point *a);
void		 ece_point_free(const struct ec_edwards *ec,
		 struct ec_point *a);
void		 ece_point_normalize(const struct ec_edwards *ec,
		 struct ec_point *a);
void		 ece_scale(const struct ec_edwards *ec, struct ec_point **a,
		 const struct bn *b);
void		 ece_dbl(const struct ec_edwards *ec, struct ec_point *a);
void		 ece_add(const struct ec_edwards *ec, struct ec_point *a,
		 const struct ec_point *b);



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
void		 edc_verify(const struct edc *edc, const uint8_t *msg,
		 int mlen);
#endif
