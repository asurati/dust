/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _BN_H_
#define _BN_H_

#include <stdint.h>
#include <stdlib.h>

struct bn;

#define BN_INVALID			(struct bn *)NULL

void		 bn_print(const char *msg, const struct bn *b);

void		 bn_add(struct bn *a, const struct bn *b);
void		 bn_sub(struct bn *a, const struct bn *b);
void		 bn_mul(struct bn *a, const struct bn *b);
void		 bn_div(struct bn *a, const struct bn *b, struct bn **r);
void		 bn_mod(struct bn *a, const struct bn *b);
void		 bn_shl(struct bn *a, int c);
void		 bn_shr(struct bn *a, int c);
void		 bn_gcd(struct bn *a, const struct bn *b);

char		 bn_mod_inv(struct bn *a, const struct bn *m);
void		 bn_mod_pow(struct bn *a, const struct bn *e,
		 const struct bn *m);
void		 bn_mod_sqrt(struct bn *a, const struct bn *m);

struct bn	*bn_new_zero();
struct bn	*bn_new_from_int(int v);
struct bn	*bn_new_from_bytes(const uint8_t *bytes, int len);
struct bn	*bn_new_from_string(const char *str, int radix);
struct bn	*bn_new_copy(const struct bn *b);
struct bn	*bn_new_prob_prime(int nbits);

void		 bn_free(struct bn *b);
#endif
