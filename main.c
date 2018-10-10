/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <bn.h>

int main()
{
	struct bn *a;
	a = bn_new_prob_prime(256);
	bn_print(a);
	return 0;
}
