/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>

#include <rndm.h>

/* Returns a big-endian byte-array. */
void rndm_fill(void *bytes, int nbits)
{
	int len, i;
	uint8_t *p;
	struct timeval tv;

	assert(nbits > 0);

	len = nbits >> 3;
	nbits &= 7;
	if (nbits)
		++len;

	p = bytes;
	memset(p, 0, len);

	/* Not cryptographically secure. */
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);

	for (i = len - 1; i >= 0; --i)
		p[i] = rand() & 0xff;

	/* Zero extranous bits in the msb. */
	if (nbits)
		p[0] &= (1 << nbits) - 1;
}
