/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sys/bn.h>

/* 'Little Endian' storage - lowest significant limb at index 0. */

limb_t limb_add(struct limbs *a, int ia, int na, const struct limbs *b,
		int ib, int nb)
{
	int i;
	limb2_t r;

	assert(na >= 0);
	assert(nb >= 0);
	assert(na >= nb);

	r = 0;
	for (i = 0; i < na; ++i) {
		r += a->l[i + ia];
		if (i < nb)
			r += b->l[i + ib];
		a->l[i + ia] = r;
		r >>= LIMB_BITS;
	}
	assert(r == 0 || r == 1);
	return r;
}

limb_t limb_sub(struct limbs *a, int ia, int na, const struct limbs *b,
		int ib, int nb)
{
	int i;
	limb2_t r;

	assert(na >= 0);
	assert(nb >= 0);
	assert(na >= nb);

	r = 0;
	for (i = 0; i < na; ++i) {
		/* r is the borrow: 0 or -1. */
		r += a->l[i + ia];
		if (i < nb)
			r -= b->l[i + ib];
		a->l[i + ia] = r;
		r = (slimb2_t)r >> LIMB_BITS;
	}
	assert(r == 0 || r == (limb2_t)-1);
	return r;
}

void limb_and(struct limbs *a, int na, const struct limbs *b, int nb)
{
	int i, mn;

	assert(na >= 0);
	assert(nb >= 0);

	mn = na <= nb ? na : nb;

	for (i = 0; i < na; ++i) {
		if (i < mn)
			a->l[i] &= b->l[i];
		else
			a->l[i] = 0;
	}
}

limb_t limb_cmp(const struct limbs *a, int na, const struct limbs *b, int nb)
{
	int diff, i;

	assert(na >= 0);
	assert(nb >= 0);

	/* Skip initial zeroes. */
	for (i = na - 1; i >= 0; --i)
		if (a->l[i])
			break;
	na = i + 1;

	/* Skip initial zeroes. */
	for (i = nb - 1; i >= 0; --i)
		if (b->l[i])
			break;
	nb = i + 1;

	diff = na - nb;
	if (diff)
		return diff;

	for (i = na - 1; i >= 0; --i) {
		if (a->l[i] > b->l[i])
			return 1;
		else if (a->l[i] < b->l[i])
			return -1;
	}
	return 0;
}

limb_t limb_mul(struct limbs *a, int na, limb_t b)
{
	int i;
	limb2_t r;

	assert(na >= 0);

	r = 0;
	for (i = 0; i < na; ++i) {
		r += (limb2_t)a->l[i] * b;
		a->l[i] = r;
		r >>= LIMB_BITS;
	}
	return r;
}

/* The function assumes space available. */
void limb_shl(struct limbs *a, int na_prev, int na_curr, int c)
{
	int i, ls;

	ls = c >> LIMB_BITS_LOG;
	c &= LIMB_BITS_MASK;

	memset(a->l + na_prev, 0, (na_curr - na_prev) << LIMB_BYTES_LOG);

	/* Perform full limb-wise shifts. */
	memmove(a->l + ls, a->l, na_prev << LIMB_BYTES_LOG);

	/* Zero the least significant limbs. */
	memset(a->l, 0, ls << LIMB_BYTES_LOG);

	/* No sub-limb shifts necessary. */
	if (c == 0)
		return;

	i = na_curr - 1;
	a->l[i] <<= c;
	for (--i; i >= ls; --i) {
		/* Take the top c bits of [i] and paste them into the bottom
		 * c bits of [i + 1]
		 */
		a->l[i + 1] |= a->l[i] >> (LIMB_BITS - c);
		a->l[i] <<= c;
	}
}

void limb_shr(struct limbs *a, int na_prev, int na_curr, int c)
{
	int ls, i;

	ls = c >> LIMB_BITS_LOG;
	c &= LIMB_BITS_MASK;

	/* Perform full limb-wise shifts. */
	memmove(a->l, a->l + ls, (na_prev - ls) << LIMB_BYTES_LOG);
	memset(a->l + na_prev - ls, 0, ls << LIMB_BYTES_LOG);

	/* No sub-limb shifts necessary. */
	if (c == 0)
		return;

	/*
	 * If na_prev != na_curr, loop until na_curr + 1. Else, na_curr.
	 * This is to collect any bits from the discarded limbs.
	 */
	ls = na_prev == na_curr ? na_prev : na_curr + 1;
	i = 0;
	a->l[i] >>= c;
	for (++i; i < ls; ++i) {
		/* Take the bottom c bits of [i] and paste them into the top
		 * c bits of [i - 1]
		 */
		a->l[i - 1] |= a->l[i] << (LIMB_BITS - c);
		a->l[i] >>= c;
	}
}
