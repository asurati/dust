/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_BN_H_
#define _SYS_BN_H_

#include <bn.h>

#include <sys/list.h>

typedef uint32_t limb_t;
typedef uint64_t limb2_t;
typedef int64_t slimb2_t;

#define LIMB_BITS			32
#define LIMB_BITS_LOG			5
#define LIMB_BYTES			(LIMB_BITS >> 3)
#define LIMB_BITS_MASK			(LIMB_BITS - 1)
#define LIMB_BYTES_MASK			(LIMB_BYTES - 1)
#define LIMB_BYTES_LOG			(LIMB_BITS_LOG - 3)
#define LIMB_FMT_STR			"%08x"

struct limbs {
	struct list_head entry;
	int n;	/* # of limbs in the array. */
	limb_t l[];
};

limb_t	limb_add(struct limbs *a, int ia, int na, const struct limbs *b,
		int ib, int nb);
limb_t	limb_sub(struct limbs *a, int ia, int na, const struct limbs *b,
		int ib, int nb);
void	limb_and(struct limbs *a, int na, const struct limbs *b, int nb);
limb_t	limb_cmp(const struct limbs *a, int na, const struct limbs *b, int nb);
void	limb_shl(struct limbs *a, int na_prev, int na_curr, int c);
void	limb_shr(struct limbs *a, int na_prev, int na_curr, int c);
limb_t	limb_mul(struct limbs *a, int na, limb_t b);

#define BN_LIMBS_INVALID		(struct limbs *)NULL
#define BN_POOL_INVALID			(struct bn_pool *)NULL

struct bn {
	struct list_head entry;
	struct limbs *l;
	int nsig;	/* # of significant limbs.  */
	int neg;
};

#define NUM_FREE_BN				128
#define NUM_LIMB_SIZES				12

struct bn_pool {
	void *nums;
	void *limbs;
	int nfree_nums;
	struct list_head free_nums;
	int nfree_limbs[NUM_LIMB_SIZES];
	struct list_head free_limbs[NUM_LIMB_SIZES];
	int npeak_limbs[NUM_LIMB_SIZES];
};

#define to_bn(e)		(list_entry(e, struct bn, entry))
#define to_limbs(e)		(list_entry(e, struct limbs, entry))

struct bn_ctx_mont {
	int msb;		/* MSSB in m. */
	struct bn *m;		/* Modulus. Odd and >= 3. */
	struct bn *r;		/* Reducer. */
	struct bn *rinv;	/* r' = Reducer's Inverse Mod m. */
	struct bn *mask;	/* Modulo R operation (AND). */
	struct bn *factor;	/* = (rr' - 1) / m. */
	struct bn *one;		/* 1 in Montgomery form for the given m. */
};

static __inline__ int bn_bsr(limb_t v)
{
	int msb;
#ifdef __powerpc__
	__asm__ volatile("cntlz %0, %1\t\n" : "=r" (msb) : "r" (v));
	msb = LIMB_BITS - msb - 1;
#else
	__asm__ volatile("bsr %1, %0\t\n" : "=r" (msb) : "r" (v));
#endif
	return msb;
}
#endif
