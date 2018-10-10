/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <rndm.h>

void rndm_fill(uint8_t *bytes, int nbits)
{
	int len, i;
	struct timespec tp;

	assert(nbits > 0);

	len = nbits >> 3;
	nbits &= 7;
	if (nbits)
		++len;

	memset(bytes, 0, len);

	clock_gettime(CLOCK_REALTIME, &tp);
	srand(tp.tv_nsec);

	for (i = len - 1; i >= 0; --i)
		bytes[i] = rand() & 0xff;

	/* Zero extranous bits in the msb. */
	if (nbits)
		bytes[0] &= (1 << nbits) - 1;
}
