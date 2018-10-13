/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_LIMB_H_
#define _SYS_LIMB_H_

#include <stdint.h>

typedef uint32_t limb_t;
typedef uint64_t limb2_t;
typedef int64_t slimb2_t;

#define LIMB_BITS			32
#define LIMB_BYTES			4
#define LIMB_BITS_MASK			(LIMB_BITS - 1)
#define LIMB_BYTES_MASK			(LIMB_BYTES - 1)
#define LIMB_BITS_LOG			5
#define LIMB_BYTES_LOG			2
#define LIMB_FMT_STR			"%08x"

limb_t		 limb_add(limb_t *a, int na, const limb_t *b, int nb);
limb_t		 limb_sub(limb_t *a, int na, const limb_t *b, int nb);
void		 limb_and(limb_t *a, int na, const limb_t *b, int nb);
limb_t		 limb_mul(limb_t *a, int na, limb_t b);
void		 limb_shl(limb_t *a, int na_prev, int na_curr, int c);
void		 limb_shr(limb_t *a, int na_prev, int na_curr, int c);

int		 limb_cmp(const limb_t *a, int na, const limb_t *b, int nb);
#endif
