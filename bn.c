/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <sys/bn.h>
#include <rndm.h>

static struct bn_pool *g_pool = BN_POOL_INVALID;

static const int bn_nlimbs[NUM_LIMB_SIZES] = {
	1,2,4,8,
	16,32,64,128,
	256,512,1024,2048
};

static const int limbs_nfree[NUM_LIMB_SIZES] = {
	20,20,20,20,
	30,20,10,10,
	10,10,10,10
};

static struct bn_pool *bn_pool_new()
{
	int i, j, nlimbs, sz;
	struct bn_pool *p;
	struct bn *tbn;
	struct limbs *tl;

	p = malloc(sizeof(*p));
	assert(p);

	p->nfree_nums = 128;
	init_list_head(&p->free_nums);
	for (i = 0; i < 128; ++i) {
		tbn = malloc(sizeof(*tbn));
		assert(tbn);
		list_add(&tbn->entry, &p->free_nums);
	}

	for (i = 0; i < NUM_LIMB_SIZES; ++i) {
		init_list_head(&p->free_limbs[i]);
		p->npeak_limbs[i] = 0;
		p->nfree_limbs[i] = limbs_nfree[i];
		nlimbs = bn_nlimbs[i];
		sz = sizeof(*tl) + (nlimbs << LIMB_BYTES_LOG);
		for (j = 0; j < limbs_nfree[i]; ++j) {
			tl = malloc(sz);
			tl->n = nlimbs;
			assert(tl);
			list_add(&tl->entry, &p->free_limbs[i]);
		}
	}
	return p;
}

static void bn_pool_free(struct bn_pool *p)
{
	int i;
	struct bn *tbn;
	struct limbs *tl;
	struct list_head *e;

	assert(p->nfree_nums == 128);
	while (!list_empty(&p->free_nums)) {
		e = list_del_head(&p->free_nums);
		tbn = to_bn(e);
		free(tbn);
	}

	for (i = 0; i < NUM_LIMB_SIZES; ++i) {
		// printf("peak[%d] = %d\n", bn_nlimbs[i], p->npeak_limbs[i]);
		assert(p->nfree_limbs[i] == limbs_nfree[i]);
		while (!list_empty(&p->free_limbs[i])) {
			e = list_del_head(&p->free_limbs[i]);
			tl = to_limbs(e);
			assert(tl->n == bn_nlimbs[i]);
			free(tl);
		}
	}
	free(p);
}

static struct bn *bn_pool_get_bn(struct bn_pool *p)
{
	struct list_head *e;
	struct bn *b;

	assert(p->nfree_nums > 0 && p->nfree_nums <= 128);

	--p->nfree_nums;
	e = list_del_head(&p->free_nums);
	b = to_bn(e);
	b->nsig = b->neg = -1;
	b->l = BN_LIMBS_INVALID;
	return b;
}

static struct limbs *bn_pool_get_limbs(struct bn_pool *p, int n)
{
	int i, diff;
	struct limbs *tl;
	struct list_head *e;

	assert(n >= 0);

	if (n == 0)
		return BN_LIMBS_INVALID;

	/* XXX arch specific. */
	asm volatile("bsr %1, %0\t\n" : "=r" (i) : "r" (n));
	if ((1 << i) != n)
		++i;

	/*
	for (i = 0; i < NUM_LIMB_SIZES; ++i)
		if (bn_nlimbs[i] >= n)
			break;
			*/

	assert(i < NUM_LIMB_SIZES);
	assert(p->nfree_limbs[i] > 0 && p->nfree_limbs[i] <= limbs_nfree[i]);

	--p->nfree_limbs[i];
	e = list_del_head(&p->free_limbs[i]);
	tl = to_limbs(e);
	assert(tl->n == bn_nlimbs[i]);

	diff = limbs_nfree[i] - p->nfree_limbs[i];
	if (diff > p->npeak_limbs[i])
		p->npeak_limbs[i] = diff;

	memset(tl->l, -1, tl->n << LIMB_BYTES_LOG);
	return tl;
}

static void bn_pool_put_limbs(struct bn_pool *p, struct limbs *tl)
{
	int i;

	assert(tl != BN_LIMBS_INVALID);

	/* XXX arch specific. */
	asm volatile("bsr %1, %0\t\n" : "=r" (i) : "r" (tl->n));
	if ((1 << i) != tl->n)
		++i;

	assert(i < NUM_LIMB_SIZES);
	assert(p->nfree_limbs[i] >= 0 && p->nfree_limbs[i] < limbs_nfree[i]);

	++p->nfree_limbs[i];
	memset(tl->l, -1, tl->n << LIMB_BYTES_LOG);
	list_add(&tl->entry, &p->free_limbs[i]);
}

/* Also puts the limbs allocated to this bn. */
static void bn_pool_put_bn(struct bn_pool *p, struct bn *b)
{
	assert(b != BN_INVALID);

	assert(p->nfree_nums >= 0 && p->nfree_nums < 128);
	if (b->l != BN_LIMBS_INVALID)
		bn_pool_put_limbs(p, b->l);

	b->nsig = b->neg = -1;
	b->l = BN_LIMBS_INVALID;

	++p->nfree_nums;
	list_add(&b->entry, &p->free_nums);
}

static void bn_zero(struct bn *b)
{
	if (b->l != BN_LIMBS_INVALID)
		bn_pool_put_limbs(g_pool, b->l);
	b->l = BN_LIMBS_INVALID;
	b->nsig = b->neg = 0;
}

static void bn_nsig_invariant(const struct bn *b)
{
	assert(bn_is_zero(b) || b->l->l[b->nsig - 1]);
}

/* Go to the next bn_nlimbs level. */
static void bn_expand(struct bn *b, int n)
{
	struct limbs *tl, *tlnew;

	assert(n >= 0);
	assert(n <= bn_nlimbs[NUM_LIMB_SIZES - 1]);

	tl = b->l;
	assert(tl == BN_LIMBS_INVALID ||
	       tl->n < bn_nlimbs[NUM_LIMB_SIZES - 1]);

	/* If the current allocation is sufficient, return. */
	if (tl != BN_LIMBS_INVALID && tl->n >= n)
		return;

	/* Else allocate. */
	tlnew = bn_pool_get_limbs(g_pool, n);
	if (tl != BN_LIMBS_INVALID) {
		assert(tlnew->n > tl->n);
		memcpy(tlnew->l, tl->l, tl->n << LIMB_BYTES_LOG);
		bn_pool_put_limbs(g_pool, tl);
	}
	b->l = tlnew;
}

static void bn_push_back(struct bn *b, limb_t v)
{
	bn_expand(b, b->nsig + 1);
	b->l->l[b->nsig] = v;
	++b->nsig;
}

static void bn_snap(struct bn *b)
{
	int i;

	for (i = b->nsig - 1; i >= 0; --i)
		if (b->l->l[i])
			break;
	++i;

	/* No change. */
	if (i == b->nsig)
		return;

	if (i == 0)
		bn_zero(b);
	b->nsig = i;
}

/* TODO check validity of the bit input. */
char bn_test_bit(const struct bn *b, int ix)
{
	int l;

	assert(ix >= 0);
	assert(!bn_is_zero(b));
	assert(ix <= (b->l->n << LIMB_BITS_LOG) - 1);

	l = ix >> LIMB_BITS_LOG;
	ix &= LIMB_BITS_MASK;
	return b->l->l[l] & ((limb_t)1 << ix) ? 1 : 0;
}

static char bn_is_even(const struct bn *b)
{
	if (bn_is_zero(b))
		return 1;
	return (b->l->l[0] & 1) == 0;
}

static void bn_rev_limbs(struct bn *b)
{
	int i;
	limb_t t;

	/* Reverse the order of the q limbs. */
	for (i = 0; i < b->nsig >> 1; ++i) {
		t = b->l->l[i];
		b->l->l[i] = b->l->l[b->nsig - i - 1];
		b->l->l[b->nsig - i - 1] = t;
	}
}

/* TODO arch specific bsr. */
static int bn_bsr(limb_t v)
{
	int msb;
	asm volatile("bsr %1, %0\t\n" : "=r" (msb) : "r" (v));
	return msb;
}

int bn_msb(const struct bn *b)
{
	int msb;

	bn_nsig_invariant(b);

	if(bn_is_zero(b))
		return -1;

	msb = (b->nsig - 1) << LIMB_BITS_LOG;
	msb += bn_bsr(b->l->l[b->nsig - 1]);
	return msb;
}

/* Don't allow expansion throw set bit routine. */
static void bn_set_bit(struct bn *b, int ix)
{
	int l;

	assert(ix >= 0);
	assert(!bn_is_zero(b));
	assert(ix <= (b->l->n << LIMB_BITS_LOG) - 1);

	l = ix >> LIMB_BITS_LOG;
	ix &= LIMB_BITS_MASK;
	b->l->l[l] |= (limb_t)1 << ix;
}

static void bn_mul_limb(struct bn *a, limb_t b)
{
	limb_t r;

	if (bn_is_zero(a))
		return;

	if (b == 0) {
		bn_zero(a);
		return;
	}

	r = limb_mul(a->l, a->nsig, b);
	if (r)
		bn_push_back(a, r);
	bn_nsig_invariant(a);
}

/* https://courses.csail.mit.edu/6.006/spring11/exams/notes3-karatsuba */
static void bn_mul_kar(struct bn *a, const struct bn *b)
{
	int mx, neg;
	struct bn ah, al, bh, bl, *t, *ra, *rd;

	if (bn_is_zero(a))
		return;

	if (bn_is_zero(b)) {
		bn_zero(a);
		return;
	}

	neg = a->neg != b->neg;

	if (b->nsig == 1) {
		bn_mul_limb(a, b->l->l[0]);
		if (!bn_is_zero(a))
			a->neg = neg;
		return;
	}

	if (a->nsig == 1) {
		t = bn_new_copy(b);
		bn_mul_limb(t, a->l->l[0]);
		bn_zero(a);
		*a = *t;
		if (!bn_is_zero(a))
			a->neg = neg;

		t->l = BN_LIMBS_INVALID;
		bn_free(t);
		return;
	}

	/* Find the division. */
	if (a->nsig >= b->nsig)
		mx = a->nsig;
	else
		mx = b->nsig;

	/* If mx is odd, even it. */
	if (mx & 1)
		++mx;

	/* Divide into two parts. */
	mx >>= 1;

	/* Each h,l is of at most mx limbs. */
	memset(&al, 0, sizeof(al));
	memset(&bl, 0, sizeof(bl));
	memset(&ah, 0, sizeof(ah));
	memset(&bh, 0, sizeof(bh));
	al.l = bl.l = ah.l = bh.l = BN_LIMBS_INVALID;

	al.nsig = mx < a->nsig ? mx : a->nsig;
	bl.nsig = mx < b->nsig ? mx : b->nsig;
	ah.nsig = a->nsig - al.nsig;
	bh.nsig = b->nsig - bl.nsig;

	bn_expand(&al, al.nsig);
	bn_expand(&bl, bl.nsig);
	bn_expand(&ah, ah.nsig);
	bn_expand(&bh, bh.nsig);

	memcpy(al.l->l, a->l->l, al.nsig << LIMB_BYTES_LOG);
	memcpy(bl.l->l, b->l->l, bl.nsig << LIMB_BYTES_LOG);
	memcpy(ah.l->l, a->l->l + al.nsig, ah.nsig << LIMB_BYTES_LOG);
	memcpy(bh.l->l, b->l->l + bl.nsig, bh.nsig << LIMB_BYTES_LOG);

	bn_snap(&al);
	bn_snap(&bl);
	bn_snap(&ah);
	bn_snap(&bh);

	ra = bn_new_copy(&ah);
	rd = bn_new_copy(&al);
	bn_mul_kar(ra, &bh);	/* z2. */
	bn_mul_kar(rd, &bl);	/* z0. */

	/* Wikipedia: Avoid overflow. */
	bn_sub(&al, &ah);
	bn_sub(&bh, &bl);
	bn_mul_kar(&al, &bh);
	bn_add(&al, ra);
	bn_add(&al, rd);	/* z1/re. */

	bn_shl(ra, mx << (LIMB_BITS_LOG + 1));
	bn_shl(&al, mx << LIMB_BITS_LOG);
	bn_add(ra, &al);
	bn_add(ra, rd);

	bn_zero(&al);
	bn_zero(&ah);
	bn_zero(&bl);
	bn_zero(&bh);
	bn_free(rd);

	bn_zero(a);
	*a = *ra;
	if (!bn_is_zero(a))
		a->neg = neg;
	ra->l = BN_LIMBS_INVALID;
	bn_free(ra);
	bn_nsig_invariant(a);
}

/* Subtract without considering signs of a and b. */
static void bn_sub_abs(struct bn *a, const struct bn *b)
{
	int cmp;
	struct bn *t;
	limb_t r;

	cmp = bn_cmp_abs(a, b);

	if (cmp == 0) {
		bn_zero(a);
		return;
	}

	if (cmp < 0) {
		t = bn_new_copy(b);
		assert(t->l != BN_LIMBS_INVALID);
		r = limb_sub(t->l, 0, t->nsig, a->l, 0, a->nsig);
		bn_zero(a);
		*a = *t;
		a->neg = 1;

		t->l = BN_LIMBS_INVALID;
		bn_free(t);
	} else {
		r = limb_sub(a->l, 0, a->nsig, b->l, 0, b->nsig);
		a->neg = 0;
	}
	assert(r == 0);
	bn_snap(a);
	bn_nsig_invariant(a);
}

/* Add without considering the sign. */
static void bn_add_abs(struct bn *a, const struct bn *b)
{
	limb_t r;

	/* Allocate space for the result. */
	if (a->nsig < b->nsig) {
		bn_expand(a, b->nsig);
		/* Zero the extra limbs. */
		memset(a->l->l + a->nsig, 0,
		       (b->nsig - a->nsig) << LIMB_BYTES_LOG);
		a->nsig = b->nsig;
	}

	r = limb_add(a->l, 0, a->nsig, b->l, 0, b->nsig);

	/* If carry is left-over, expand the result. */
	if (r)
		bn_push_back(a, r);
	bn_nsig_invariant(a);
}

static void bn_add_sub(struct bn *a, const struct bn *b, char add)
{
	if (add) {
		/* a + b, or -a - b. Retain the sign of a. */
		bn_add_abs(a, b);
	} else if (a->neg) {
		/* -a + b = -(a - b). */
		/* (-a) - (-b) = -a + b = -(a - b). */
		a->neg = 0;
		bn_sub_abs(a, b);
		if (!bn_is_zero(a))
			a->neg = !a->neg;
	} else {
		/* a - b. */
		bn_sub_abs(a, b);
	}
}




















int bn_is_zero(const struct bn *b)
{
	assert(b != BN_INVALID);
	return b->nsig == 0;
}

int bn_cmp_int(const struct bn *b, int v)
{
	assert(b != BN_INVALID);

	if (v == 0)
		return b->nsig == 0;

	if (b->nsig != 1)
		return 0;

	if (b->neg != (v < 0))
		return 0;

	if (v < 0)
		v = -v;

	if (b->l->l[0] == (limb_t)v)
		return 1;

	return 0;
}

int bn_is_one(const struct bn *b)
{
	return bn_cmp_int(b, 1);
}

void bn_free(struct bn *a)
{
	assert(a != BN_INVALID);
	bn_pool_put_bn(g_pool, a);
}

void bn_init()
{
	assert(g_pool == BN_POOL_INVALID);
	g_pool = bn_pool_new();
	assert(g_pool != BN_POOL_INVALID);
}

void bn_fini()
{
	assert(g_pool != BN_POOL_INVALID);
	bn_pool_free(g_pool);
	g_pool = BN_POOL_INVALID;
}

struct bn *bn_new_zero()
{
	struct bn *b;
	b = bn_pool_get_bn(g_pool);
	b->neg = 0;
	b->nsig = 0;
	b->l = BN_LIMBS_INVALID;
	return b;
}

/* Requirement: sizeof(limb) >= sizeof(int). */
struct bn *bn_new_from_int(int v)
{
	struct bn *b;

	b = bn_new_zero();
	if (v == 0)
		return b;

	if (v < 0) {
		b->neg = 1;
		v = -v;
	}

	bn_push_back(b, v);
	return b;
}

void bn_print(const char *msg, const struct bn *b)
{
	int i;
	const char *fmt;

	assert(b != BN_INVALID);

	if (msg)
		printf("%s", msg);

	if (bn_is_zero(b)) {
		printf("0\n");
		return;
	}

	if (b->neg)
		printf("-");

	fmt = "%x";
	for (i = b->nsig - 1; i >= 0; --i) {
		printf(fmt, b->l->l[i]);
		fmt = LIMB_FMT_STR;
	}
	printf("\n");
}

struct bn *bn_new_copy(const struct bn *b)
{
	struct bn *a;

	assert(b != BN_INVALID);

	a = bn_new_zero();

	if (bn_is_zero(b))
		return a;

	/* Choose nsig to allocate. */
	a->l = bn_pool_get_limbs(g_pool, b->nsig);
	a->nsig = b->nsig;
	a->neg = b->neg;
	memcpy(a->l->l, b->l->l, b->nsig << LIMB_BYTES_LOG);
	return a;
}

/* TODO sign. */
uint8_t *bn_to_bytes_le(const struct bn *b, int *len)
{
	int nbytes, i, j;
	uint8_t *bytes;

	assert(b != BN_INVALID);
	assert(len != NULL);
	assert(b->neg == 0);

	if (bn_is_zero(b)) {
		bytes = malloc(1);
		assert(bytes);
		bytes[0] = 0;
		*len = 1;
		return bytes;
	}

	nbytes = b->nsig << LIMB_BYTES_LOG;
	bytes = malloc(nbytes);
	assert(bytes);

	for (i = 0, j = 0; i < b->nsig; ++i) {
		bytes[j++] = b->l->l[i];
		bytes[j++] = b->l->l[i] >> 8;
		bytes[j++] = b->l->l[i] >> 16;
		bytes[j++] = b->l->l[i] >> 24;
	}

	assert(nbytes == j);
	*len = nbytes;
	return bytes;
}

/*
 * The bytes array, laid down from index 0 at the left to index len - 1
 * to the right is treated as one large number, as written down on
 * paper (i.e. big-endian).
 *
 * The least significant limb is at index 0.
 */
struct bn *bn_new_from_bytes(const uint8_t *bytes, int len)
{
	int i, j, k, nlimbs;
	struct bn *b;
	limb_t val;

	b = BN_INVALID;
	if (bytes == NULL || len <= 0)
		return b;

	b = bn_new_zero();

	nlimbs = (len + LIMB_BYTES_MASK) >> LIMB_BYTES_LOG;
	b->l = bn_pool_get_limbs(g_pool, nlimbs);

	k = j = val = 0;
	for (i = len - 1; i >= 0; --i) {
		val |= (uint32_t)bytes[i] << (j << 3);
		++j;

		if (j != LIMB_BYTES && i)
			continue;

		j = 0;
		b->l->l[k++] = val;
		val = 0;
	}
	b->nsig = k;
	bn_snap(b);
	return b;
}

/* The str is one large number, as written on paper (i.e. big endian). */
struct bn *bn_new_from_string(const char *str, int radix)
{
	int i, j, k, len, sz;
	unsigned char c;
	struct bn *b;
	uint8_t *bytes;

	assert(radix == 16);
	b = BN_INVALID;
	if (str == NULL || radix != 16)
		goto err0;

	/* Check valid hex strings. Allow whitespace. */
	len = strlen(str);
	sz = len >> 1;
	if (len & 1)
		++sz;

	bytes = malloc(sz);
	if (bytes == NULL)
		goto err0;

	for (i = len - 1, j = sz, k = 0; i >= 0; --i) {
		c = str[i];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
			continue;

		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a' && c <= 'f')
			c = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			c = c - 'A' + 10;
		else
			break;

		/* About to write the low nibble, so initialize. */
		if (k == 0) {
			bytes[--j] = c;
			k = 1;
		} else {
			bytes[j] |= c << 4;
			k = 0;
		}
	}

	if (i != -1)
		goto err1;
	b = bn_new_from_bytes(&bytes[j], sz - j);
err1:
	free(bytes);
err0:
	return b;
}

/* Compare without considering signs. */
int bn_cmp_abs(const struct bn *a, const struct bn *b)
{
	return limb_cmp(a->l, a->nsig, b->l, b->nsig);
}

void bn_and(struct bn *a, const struct bn *b)
{
	assert(a != BN_INVALID && b != BN_INVALID);

	if (bn_is_zero(a))
		return;

	if (bn_is_zero(b)) {
		bn_zero(a);
		return;
	}
	limb_and(a->l, a->nsig, b->l, b->nsig);
	bn_snap(a);
}

void bn_add(struct bn *a, const struct bn *b)
{
	assert(a != BN_INVALID && b != BN_INVALID);
	bn_add_sub(a, b, a->neg == b->neg);
}

void bn_sub(struct bn *a, const struct bn *b)
{
	assert(a != BN_INVALID && b != BN_INVALID);
	bn_add_sub(a, b, a->neg != b->neg);
}

void bn_shr(struct bn *a, int c)
{
	int mx, nbits;

	assert(a != BN_INVALID && c >= 0);

	if (c == 0 || bn_is_zero(a))
		return;

	/* bits utilized. */
	nbits = bn_msb(a) + 1;
	/* bits required. TODO overflow.*/
	nbits -= c;

	if (nbits <= 0) {
		bn_zero(a);
		return;
	}

	/* limbs required. */
	mx = nbits >> LIMB_BITS_LOG;
	if (nbits & LIMB_BITS_MASK)
		++mx;
	assert(mx <= a->nsig);

	limb_shr(a->l, a->nsig, mx, c);
	/*
	 * Set nsig before calling snap, to avoid hitting non-zero
	 * limbs which were discarded but not zeroed due to ls == 0.
	 */
	a->nsig = mx;
	bn_snap(a);
	bn_nsig_invariant(a);
}

void bn_shl(struct bn *a, int c)
{
	int mx, nbits;

	assert(a != BN_INVALID && c >= 0);

	if (c == 0 || bn_is_zero(a))
		return;

	/* bits utilized. */
	nbits = bn_msb(a) + 1;
	/* bits required. TODO overflow.*/
	nbits += c;

	/* limbs required. */
	mx = nbits >> LIMB_BITS_LOG;
	if (nbits & LIMB_BITS_MASK)
		++mx;

	bn_expand(a, mx);
	limb_shl(a->l, a->nsig, mx, c);
	a->nsig = mx;
	bn_nsig_invariant(a);
}

void bn_mul(struct bn *a, const struct bn *b)
{
	assert(a != BN_INVALID && b != BN_INVALID);

	bn_mul_kar(a, b);
	bn_snap(a);
	bn_nsig_invariant(a);
}

/*
 * Due to Knuth Algorithm D (Division).
 * b = 2^LIMB_BITS.
 *
 * This is a division of u = u1u2u3...um+n by v = v1v2...vn,
 * where each ui,vi is of len LIMB_BITS.
 */

void bn_div(struct bn *a, const struct bn *b, struct bn **r)
{
	int i, j, ls;
	limb_t bh, bl, ah, al, q, sr;
	limb2_t v, rem;
	struct bn *ta, *t;
	const struct bn *tb;

	assert(a != BN_INVALID && b != BN_INVALID);
	assert(!bn_is_zero(b));

	/* a is repurposed as the quotient. */
	ta = bn_new_copy(a);

	/*
	 * Normalize u and v such that v1 >= floor(b/2).
	 * Since b = 2^LIMB_BITS, v1 needs to have its MSB set for it
	 * to be >= floor(b/2).
	 */
	ls = LIMB_BITS_MASK - bn_bsr(b->l->l[b->nsig - 1]);
	if (ls) {
		/* Only allocate tb if there's a need to shift. */
		t = bn_new_copy(b);

		bn_shl(ta, ls);
		bn_shl(t, ls);
		tb = t;
	} else {
		tb = b;
	}

	/* XXX: Violation of the l[nsig - 1] != 0 rule. */
	if (ta->nsig == a->nsig)
		bn_push_back(ta, 0);

	bh = tb->l->l[tb->nsig - 1];
	if (tb->nsig > 1)
		bl = tb->l->l[tb->nsig - 2];
	else
		bl = 0;

	/*
	 *  Now divide uj uj+1 with v1 to get a single quotient limb qj.
	 *  j must be such that j - n >= 0, or j >= n, where n is tb->nsig
	 */
	for (i = 0, j = ta->nsig - 1; j >= tb->nsig; --j, ++i) {
		ah = ta->l->l[j];
		al = ta->l->l[j - 1];

		v   = ah;
		v <<= LIMB_BITS;
		v  |= al;

		/* Step D3. */
		if (ah == bh)
			q = -1;	/* 2^LIMB_BITS - 1. */
		else
			q = v / bh;

		if (q == 0) {
			/* Step D5. */
			a->l->l[i] = q;
			continue;
		}

		/* Step D3. Test for v2*q. */
		while (1) {
			rem = v - (limb2_t)q * bh;
			/*
			 * If the high limb of the rem is set, the remainder,
			 * after j - 2 is appended, will be greater than
			 * q * bl. TODO proof, or use big num for the
			 * calculations.
			 */
			if (rem >> LIMB_BITS)
				break;
			rem <<= LIMB_BITS;
			rem |= ta->l->l[j - 2];

			/* v2 * q is less. */
			if ((limb2_t)q * bl <= rem)
				break;
			--q;
			rem >>= LIMB_BITS;
			rem += bh;
		}

		if (q == 0) {
			/* Step D5. */
			a->l->l[i] = q;
			continue;
		}

		/*
		 * Step D4.
		 * Here, n == # of limbs of v or b == tb->nsig.
		 * From the book, uj uj+1 ... uj+n -= (v1 v2 ... vn) * q.
		 * For us,
		 * ta[j] ta[j - 1] ... ta[j - n] -= (tbn-1 tbn-2 ... tb0) * q;
		 * See note above about j - n >= 0 determining the loop
		 * control condition.
		 *
		 * The # of elements involved in subtraction are:
		 * ta: n + 1, i.e. tb->nsig + 1.
		 * t * q: n or n + 1
		 */
		t = bn_new_copy(tb);
		bn_mul_limb(t, q);

		assert(t->nsig == tb->nsig || t->nsig == tb->nsig + 1);

		sr = limb_sub(ta->l, j - tb->nsig, tb->nsig + 1, t->l, 0,
			      t->nsig);
		if (sr) {
			--q;
			sr += limb_add(ta->l, j - tb->nsig, tb->nsig + 1,
				       tb->l, 0, tb->nsig);
		}
		assert(sr == 0);

		bn_free(t);

		/* Step D5. */
		a->l->l[i] = q;
	}

	if (ls)
		bn_free((struct bn *)tb);

	/* Form the quotient. */
	if (i == 0) {
		bn_zero(a);
	} else {
		a->nsig = i;
		bn_rev_limbs(a);
		bn_snap(a);
	}

	if (r == NULL) {
		bn_free(ta);
		return;
	}

	/* Form the remainder. */
	bn_snap(ta);
	bn_shr(ta, ls);
	assert(*r == BN_INVALID);
	*r = ta;
}

void bn_mod(struct bn *a, const struct bn *b)
{
	struct bn *ta;
	struct bn *rem = BN_INVALID;

	ta = bn_new_copy(a);

	bn_div(a, b, &rem);

	bn_mul(a, b);
	bn_add(a, rem);
	assert(bn_cmp_abs(a, ta) == 0);
	bn_free(ta);

	bn_zero(a);
	*a = *rem;
	rem->l = BN_LIMBS_INVALID;
	bn_free(rem);
}

/* Binary GCD algorithm. */
void bn_gcd(struct bn *a, const struct bn *b)
{
	int i, ea, eb, cmp;
	struct bn *tb, *gcd;

	assert(a != BN_INVALID && b != BN_INVALID);

	/* Only +ve for now. */
	assert(a->neg == 0);
	assert(b->neg == 0);

	tb = bn_new_copy(b);

	i = 0;
	gcd = BN_INVALID;
	for (;;) {
		if (bn_is_zero(tb)) {
			gcd = a;
			break;
		} else if (bn_is_zero(a)) {
			gcd = tb;
			break;
		}

		ea = bn_is_even(a);
		eb = bn_is_even(tb);
		if (ea && eb) {
			++i;
			bn_shr(a, 1);
			bn_shr(tb, 1);
		} else if (ea) {
			bn_shr(a, 1);
		} else if (eb) {
			bn_shr(tb, 1);
		} else {
			cmp = bn_cmp_abs(a, tb);
			if (cmp >= 0) {
				bn_sub(a, tb);
				bn_shr(a, 1);
			} else {
				bn_sub(tb, a);
				bn_shr(tb, 1);
			}
		}
	}

	bn_shl(gcd, i);
	bn_snap(gcd);
	if (gcd == tb) {
		*a = *tb;
		tb->l = BN_LIMBS_INVALID;
	}
	bn_free(tb);
}

char bn_mod_inv(struct bn *a, const struct bn *m)
{
	struct bn *t, *rem, *r0, *r1, *s0, *s1;
	assert(a != BN_INVALID && m != BN_INVALID);

	/* Only +ve for now. */
	assert(a->neg == 0);
	assert(m->neg == 0);

	/*
	 * Since we need to destroy a in order to find the inverse, if
	 * it turns out later that the inverse cannot exist, we want a to
	 * remain untouched. Hence, work on a copy.
	 */
	r0 = bn_new_copy(a);
	r1 = bn_new_copy(m);

	s0 = bn_new_from_int(1);
	s1 = bn_new_zero();

	/*
	 * r0, r1, s0, s1 from the table in the Wiki article.
	 * sa + tm = gcd(a,m). If the gcd is 1, then
	 * sa === 1 mod m (since tm mod m = 0), or
	 * s is the modular inverse needed.
	 */

	for (;;) {
		rem = BN_INVALID;
		bn_div(r0, r1, &rem);
		/* r0 is the quotient. */

		/* If the remainder is 0, done. */
		if (bn_is_zero(rem)) {
			bn_free(r0);
			bn_free(s0);
			bn_free(rem);
			break;
		}

		/*
		 * s0 - r0 * s1. Then, current s1 becomes the next s0, and
		 * the result becomes the next s1.
		 * s0' = s1;
		 * s1' = s0 - r0 *s1;
		 */
		bn_mul(r0, s1);	/* r0 * s1. */
		bn_sub(s0, r0);	/* s0 - r0 * s1. */
		bn_free(r0);

		t = s1;
		s1 = s0;
		s0 = t;

		/* Current r1 is the next r0. Current rem is the next r1. */
		r0 = r1;
		r1 = rem;
	}


	/* r1 has the gcd. If it is not 1, inverse does not exist. */
	bn_snap(r1);
	if (!bn_is_one(r1)) {
		bn_free(s1);
		bn_free(r1);
		return 0;
	}
	bn_free(r1);

	/* s1 is the required inverse. If it is -ve, add m. */
	if (s1->neg) {
		bn_add(s1, m);
		assert(s1->neg == 0);
	}
	bn_snap(s1);

	bn_zero(a);
	*a = *s1;
	s1->l = BN_LIMBS_INVALID;
	bn_free(s1);
	return 1;
}











/* Montgomery calculations. */

struct bn_ctx_mont *bn_ctx_mont_new(const struct bn *m)
{
	int msb;
	struct bn *one, *t;
	struct bn_ctx_mont *ctx;

	/* Montgomery. Restrict to odd, >= 3 m. */
	assert(!bn_is_even(m));

	msb = bn_msb(m);
	assert(msb >= 1);

	ctx = malloc(sizeof(*ctx));
	assert(ctx);
	ctx->msb = msb;
	ctx->m = bn_new_copy(m);

	one = bn_new_from_int(1);

	ctx->r = bn_new_copy(one);
	bn_shl(ctx->r, msb + 1);

	ctx->mask = bn_new_copy(ctx->r);
	bn_sub(ctx->mask, one);

	ctx->one = bn_new_copy(ctx->r);
	bn_mod(ctx->one, m);

	ctx->rinv = bn_new_copy(ctx->r);
	bn_mod_inv(ctx->rinv, m);

	t = bn_new_copy(ctx->r);
	bn_mul(t, ctx->rinv);	/* rr'. */
	ctx->factor = bn_new_copy(t);

	/* Check rr' == 1 mod m. */
	bn_mod(t, m);
	assert(bn_is_one(t));
	bn_free(t);
	t = BN_INVALID;

	bn_sub(ctx->factor, one);
	bn_div(ctx->factor, m, &t);
	assert(bn_is_zero(t));
	bn_free(t);
	bn_free(one);
	return ctx;
}

void bn_ctx_mont_free(struct bn_ctx_mont *ctx)
{
	assert(ctx);
	bn_free(ctx->m);
	bn_free(ctx->r);
	bn_free(ctx->rinv);
	bn_free(ctx->factor);
	bn_free(ctx->one);
	bn_free(ctx->mask);
	free(ctx);
}

void bn_to_mont(const struct bn_ctx_mont *ctx, struct bn *b)
{
	assert(ctx);
	assert(b);

	if (bn_is_zero(b))
		return;
	bn_shl(b, ctx->msb + 1);
	bn_mod(b, ctx->m);
}

void bn_from_mont(const struct bn_ctx_mont *ctx, struct bn *b)
{
	assert(ctx);
	assert(b);

	if (bn_is_zero(b))
		return;
	bn_mul(b, ctx->rinv);
	bn_mod(b, ctx->m);
}

/* a and b are in Montgomery form. */
void bn_sub_mont(const struct bn_ctx_mont *ctx, struct bn *a,
		 const struct bn *b)
{
	assert(a->neg == 0);
	assert(b->neg == 0);
	assert(bn_cmp_abs(a, ctx->m) < 0);
	assert(bn_cmp_abs(b, ctx->m) < 0);

	bn_sub(a, b);
	if (a->neg)
		bn_add(a, ctx->m);
	else
		bn_mod(a, ctx->m);
	assert(a->neg == 0);
	assert(bn_cmp_abs(a, ctx->m) < 0);
}

/* a and b are in Montgomery form. */
void bn_add_mont(const struct bn_ctx_mont *ctx, struct bn *a,
		 const struct bn *b)
{
	assert(a->neg == 0);
	assert(b->neg == 0);
	assert(bn_cmp_abs(a, ctx->m) < 0);
	assert(bn_cmp_abs(b, ctx->m) < 0);

	bn_add(a, b);
	bn_mod(a, ctx->m);
}

/* a and b are in Montgomery form. */
void bn_mul_mont(const struct bn_ctx_mont *ctx, struct bn *a,
		 const struct bn *b)
{
	struct bn *t;

	assert(a->neg == 0);
	assert(b->neg == 0);
	assert(bn_cmp_abs(a, ctx->m) < 0);
	assert(bn_cmp_abs(b, ctx->m) < 0);

	bn_mul(a, b);
	t = bn_new_copy(a);
	bn_and(a, ctx->mask);
	bn_mul(a, ctx->factor);
	bn_and(a, ctx->mask);
	bn_mul(a, ctx->m);
	bn_add(a, t);
	bn_shr(a, ctx->msb + 1);

	if (bn_cmp_abs(a, ctx->m) >= 0)
		bn_sub(a, ctx->m);

	bn_free(t);
	assert(bn_cmp_abs(a, ctx->m) < 0);
}

/*
 * a and pow are in Montgomery form, e is a regular number.
 * Binary right-to-left.
 */
void bn_mod_pow_mont(const struct bn_ctx_mont *ctx,
		     struct bn *a, const struct bn *e)
{
	int i, nbits;
	struct bn *pow;

	/* If a is 0, return 0. */
	if (bn_is_zero(a))
		return;

	nbits = bn_msb(e) + 1;
	pow = bn_new_copy(ctx->one);
	for (i = 0; i < nbits; ++i) {
		if (bn_test_bit(e, i))
			bn_mul_mont(ctx, pow, a);
		if (i < nbits - 1)
			bn_mul_mont(ctx, a, a);
	}
	bn_zero(a);
	*a = *pow;
	pow->l = BN_LIMBS_INVALID;
	bn_free(pow);
}

/* a^e % m. */
void bn_mod_pow(struct bn *a, const struct bn *e, const struct bn *m)
{
	struct bn_ctx_mont *ctx;

	assert(a != BN_INVALID);
	assert(e != BN_INVALID);
	assert(m != BN_INVALID);

	/* If a is 0, return 0. */
	if (bn_is_zero(a))
		return;
	ctx = bn_ctx_mont_new(m);
	bn_to_mont(ctx, a);
	bn_mod_pow_mont(ctx, a, e);
	bn_from_mont(ctx, a);
	bn_ctx_mont_free(ctx);
}

/*
 * http://www.math.vt.edu/people/brown/class_homepages/shanks_tonelli.pdf
 *
 * Tonelli-Shanks. m must be an odd prime, and gcd(a,m) == 1. The second
 * condition applies when a is an element of the prime field defined over m,
 * the only usecase for this function at the moment.
 */
void bn_mod_sqrt(struct bn *a, const struct bn *m)	/* m == modulus. */
{
	int bits, i, r, found;
	struct bn *exp, *t, *s, *q, *one, *ma;
	struct bn *x, *b, *g;
	struct bn_ctx_mont *ctx;

	assert(a->neg == 0);
	assert(m->neg == 0);

	one = bn_new_from_int(1);

	ctx = bn_ctx_mont_new(m);

	/* Convert a into Montgomery form. */
	bn_to_mont(ctx, a);
	ma = bn_new_copy(a);

	/* First: Euler's criterion to check if the sqrt exists. */
	exp = bn_new_copy(m);
	bn_sub(exp, one);
	s = bn_new_copy(exp);	/* s = m - 1 */
	bn_shr(exp, 1);		/* exp = (m - 1) / 2 */

	bn_mod_pow_mont(ctx, a, exp);
	/* The result is not 1. Hence, sqrt does not exist. */
	if (bn_cmp_abs(a, ctx->one))
		assert(0);

	/* Find s*2^e = m - 1 */
	bits = 0;
	for (;;) {
		if (!bn_is_even(s))
			break;
		++bits;
		bn_shr(s, 1);
	}
	assert(bits > 0);

	/* Find q such that q^((m - 1) / 2)) === -1 mod p. */
	found = 0;
	q = bn_new_copy(ctx->one);
	bn_add(q, q);	/* q starts at 2. */
	for (;;) {
		/* TODO overflow. */

		/* The result should not be 0. */
		t = bn_new_copy(q);

		bn_mod_pow_mont(ctx, t, exp);
		/* The result is either 1 or -1 mod p. */

		/* Found -1 mod p, a non-square. */
		if (bn_cmp_abs(t, ctx->one))
			found = 1;
		bn_free(t);
		if (found)
			break;
		bn_add(q, ctx->one);
	}
	bn_free(exp);

	/* Initialize x, b, r, g. All in Montgomery form. */
	b = bn_new_copy(ma);
	x = bn_new_copy(ma);
	g = bn_new_copy(q);

	r = bits;
	bn_mod_pow_mont(ctx, b, s);
	bn_mod_pow_mont(ctx, g, s);
	bn_add(s, one);
	bn_shr(s, 1);	/* (s + 1) / 2 */
	bn_mod_pow_mont(ctx, x, s);

	bn_free(s);
	bn_free(ma);
	bn_free(q);

	for (;;) {
		/* Find least integer i such that b^(2^i) === 1 mod m. */
		found = 0;
		exp = bn_new_copy(one);
		for (i = 0; i < r; ++i) {
			t = bn_new_copy(b);
			bn_mod_pow_mont(ctx, t, exp);
			if (!bn_cmp_abs(t, ctx->one))
				found = 1;
			bn_free(t);
			if (found)
				break;
			bn_shl(exp, 1);
		}
		bn_free(exp);
		assert(found);
		if (i == 0)
			break;

		/* x = x * g^(2^(r-i-1)) */
		exp = bn_new_copy(one);
		bn_shl(exp, r - i - 1);
		t = bn_new_copy(g);
		bn_mod_pow_mont(ctx, t, exp);
		bn_mul_mont(ctx, x, t);
		bn_free(t);

		/* b = b * g^(2^(r-i)) */
		bn_shl(exp, 1);
		t = bn_new_copy(g);
		bn_mod_pow_mont(ctx, t, exp);
		bn_mul_mont(ctx, b, t);
		bn_free(t);

		/* g =  g^(2^(r-i)) */
		bn_mod_pow_mont(ctx, g, exp);
		bn_free(exp);

		r = i;
	}

	bn_free(b);
	bn_free(g);
	bn_free(one);

	bn_from_mont(ctx, x);
	bn_ctx_mont_free(ctx);

	bn_zero(a);
	*a = *x;
	x->l = BN_LIMBS_INVALID;
	bn_free(x);
}













#define PRIME_TEST_LIMIT 1000000

/* Fermat's. The function is quite slow. Do not use for primes > 1024 bits. */
struct bn *bn_new_prob_prime(int nbits)
{
	int nbytes, i, comp, sz, nprimes;
	uint8_t *bytes;
	struct bn *n, *a, *two, *one, *nm1, *t, *rem;
	FILE *f;
	int *primes;

	assert(nbits > 1);

	/* See primbin.txt to generate the binary. */
	f = fopen("./primes.bin", "rb");
	assert(f);
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	primes = malloc(sz);
	assert(primes);
	nprimes = fread(primes, sz, 1, f);
	fclose(f);
	nprimes = sz/sizeof(int);
	if (nprimes > PRIME_TEST_LIMIT)
		nprimes = PRIME_TEST_LIMIT;

	n = BN_INVALID;
	nbytes = nbits >> 3;
	if (nbits & 7)
		++nbytes;

	bytes = malloc(nbytes);
	if (bytes == NULL)
		goto err0;

	one = bn_new_from_int(1);
	two = bn_new_from_int(2);
	rndm_fill(bytes, nbits);

//	n = bn_new_from_string("cedbe242489741652735efb448dc4105", 16);
//	n = bn_new_from_string("3fc237c0331dc23265e6e2c76af63bef", 16);

	n = bn_new_from_bytes(bytes, nbytes);
	if (n == BN_INVALID)
		goto err1;

	bn_set_bit(n, 0);
	bn_set_bit(n, nbits - 1);
	for (;;) {
		/* TODO Handle Overflow. */
		if (bn_msb(n) >= nbits)
			assert(0);
		bn_print(NULL, n);

		comp = 0;
		a = bn_new_copy(one);
		t = bn_new_copy(n);

		for (i = 0; i < nprimes && comp == 0; ++i) {
			rem = BN_INVALID;
			a->l->l[0] = primes[i];
			if (bn_cmp_abs(t, a) >= 0)
				break;

			/* bn_div does not change the allocation of t->l->l .*/
			bn_div(t, a, &rem);
			if (bn_is_zero(rem)) {
				comp = 1;
			} else {
				memcpy(t->l->l, n->l->l,
				       n->nsig << LIMB_BYTES_LOG);
				t->nsig = n->nsig;
			}
			bn_free(rem);
		}
		bn_free(t);
		bn_free(a);

		if (comp) {
			bn_add(n, two);
			continue;
		}

		a = bn_new_copy(two);
		nm1 = bn_new_copy(n);
		bn_sub(nm1, one);

		for (i = 0; i < 10; ++i) {
			/* TODO check a with n - 2. */
			t = bn_new_copy(a);
			bn_mod_pow(t, nm1, n);
			if (!bn_is_one(t)) {
				bn_free(t);
				break;
			}
			bn_free(t);
			bn_add(a, one);
		}
		bn_free(a);
		bn_free(nm1);
		if (i == 10)
			break;
		bn_add(n, two);
	}
	bn_free(one);
	bn_free(two);
err1:
	free(bytes);
err0:
	return n;
}
