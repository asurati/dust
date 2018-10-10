/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <bn.h>

const char *sl =
"44ae673a4cda87d13b068cf27840d87e5f3ab444c2318da97515f99e596b"
"1162e09a66315680ab97a71fd084b7de7e1f0ba5386c949e8b6594656129"
"ee65715";

const char *ss = "9cabc0e6 f3634fff f68a1548";
const char *st = "13 95781cde 6c69fffe d142a900";

const char *mm = "40adbc6b19cf399c258ad4b1d27e128fa3322758b99b866042f4fedc"
"60b200a05fbc0b798b4415b0cfea61";
const char *aa = "6c13cd835651388c48aa61bc252098b586742da7a76e9e9a6cb423";
const char *bb = "3fc237c0331dc23265e6e2c76af63bed";
const char *powa = "4000 00000000";
const char *powb = "1 00000000 00000000";
const char *te29 = "1 fe11be01 98ee1193 2f37163b";

char *moda = "1 edfbda59 47c18b87 9babfbfb d66dab81 bdf07b62 03d45756 4360584e 1378bf37 490f1799 93e93738 768549fd 436a5665 6911b312 18932a35 76481094 d51bc7e8 00000000 00000000 00000000 00000000 00000000";

char *modb = "f38f7972 ff1e1811 0d587b40 da95a12a 7f6d7d08 f2d6da79 ce64b8db f9d03f81 905b59ee 10c096cd 7ee69fb0 1634ad77 7aa72d79 0776c1f3 6be89c78 40e428a3";

const char *mula = "1afbe85412460a7f50f55adcc51a8e7adb85e23129a3835b4494a91"
"6a6a140ea16c4cedf96df15fe9320c71bdafebc19a";
const char *mulb = "b41359e418b8aca0434d806d3f4ea68bdd6de67db791134347644"
"8bb6c4e69d0fba03878755e20d50e31c7b37139a560b65469734aaffb8cf8fa519c53c99783";

const char *diva = "14c7310 e9196e90 ac810000";
const char *divb = "d80fdd51 7738d2f1 5fbac6ff 081a821f 9539ec90 c4aefabb"
"bc29bed7 f1327707";
int main()
{
	struct bn *a, *b, *c;
	a = bn_new_prob_prime(512);
//	a = bn_new_from_string(moda, 16);
//	b = bn_new_from_string(modb, 16);
//	c = bn_new_from_string("1f1", 16);
//	bn_mod(a, b);
	bn_print(a);
	(void)a;
	(void)b;
	(void)c;
	return 0;
}
