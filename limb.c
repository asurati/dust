/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sys/limb.h>

/* 'Little Endian' storage - lowest significant limb at index 0. */

limb_t limb_add(limb_t *a, int na, const limb_t *b, int nb)
{
	int i;
	limb2_t r;

	assert(na >= 0);
	assert(nb >= 0);
	assert(na >= nb);

	if (nb == 0)
		return 0;

	r = 0;
	for (i = 0; i < na; ++i) {
		r += a[i];
		if (i < nb)
			r += b[i];
		a[i] = r;
		r >>= LIMB_BITS;
	}
	assert(r == 0 || r == 1);
	return r;
}

limb_t limb_sub(limb_t *a, int na, const limb_t *b, int nb)
{
	int i;
	limb2_t r;

	assert(na >= 0);
	assert(nb >= 0);
	assert(na >= nb);

	r = 0;
	for (i = 0; i < na; ++i) {
		/* r is the borrow: 0 or -1. */
		r += a[i];
		if (i < nb)
			r -= b[i];
		a[i] = r;
		r = (slimb2_t)r >> LIMB_BITS;
	}
	assert(r == 0 || r == (limb2_t)-1);
	return r;
}

int limb_cmp(const limb_t *a, int na, const limb_t *b, int nb)
{
	int diff, i;

	assert(na >= 0);
	assert(nb >= 0);

	/* Skip initial zeroes. */
	for (i = na - 1; i >= 0; --i)
		if (a[i])
			break;
	na = i + 1;

	/* Skip initial zeroes. */
	for (i = nb - 1; i >= 0; --i)
		if (b[i])
			break;
	nb = i + 1;

	diff = na - nb;
	if (diff)
		return diff;

	for (i = na - 1; i >= 0; --i) {
		if (a[i] > b[i])
			return 1;
		else if (a[i] < b[i])
			return -1;
	}
	return 0;
}

limb_t limb_mul(limb_t *a, int na, limb_t b)
{
	int i;
	limb2_t r;

	assert(na >= 0);

	r = 0;
	for (i = 0; i < na; ++i) {
		r += (limb2_t)a[i] * b;
		a[i] = r;
		r >>= LIMB_BITS;
	}
	return r;
}

/* The function assumes space available. */
void limb_shl(limb_t *a, int na_prev, int na_curr, int c)
{
	int i, ls;

	ls = c >> LIMB_BITS_LOG;
	c &= LIMB_BITS_MASK;

	memset(a + na_prev, 0, (na_curr - na_prev) << LIMB_BYTES_LOG);

	/* Perform full limb-wise shifts. */
	memmove(a + ls, a, na_prev << LIMB_BYTES_LOG);

	/* Zero the least significant limbs. */
	memset(a, 0, ls << LIMB_BYTES_LOG);

	/* No sub-limb shifts necessary. */
	if (c == 0)
		return;

	i = na_curr - 1;
	a[i] <<= c;
	for (--i; i >= ls; --i) {
		/* Take the top c bits of [i] and paste them into the bottom
		 * c bits of [i + 1]
		 */
		a[i + 1] |= a[i] >> (LIMB_BITS - c);
		a[i] <<= c;
	}
}

void limb_shr(limb_t *a, int na_prev, int na_curr, int c)
{
	int ls, i;

	ls = c >> LIMB_BITS_LOG;
	c &= LIMB_BITS_MASK;

	/* Perform full limb-wise shifts. */
	memmove(a, a + ls, na_curr << LIMB_BYTES_LOG);
	memset(a + na_prev - ls, 0, ls << LIMB_BYTES_LOG);

	/* No sub-limb shifts necessary. */
	if (c == 0)
		return;

	/*
	 * If na_prev != na_curr, loop until na_curr + 1. Else, na_curr.
	 * This is to collect any bits from the discarded limbs.
	 */
	ls = na_prev == na_curr ? na_prev : na_curr + 1;
	i = 0;
	a[i] >>= c;
	for (++i; i < ls; ++i) {
		/* Take the bottom c bits of [i] and paste them into the top
		 * c bits of [i - 1]
		 */
		a[i - 1] |= a[i] << (LIMB_BITS - c);
		a[i] >>= c;
	}
}
