/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <rndm.h>

#include <sys/tls.h>

static uint8_t b[4096];
int tls_parse_records(const uint8_t *buf, int len, uint8_t *peerpub)
{
	int i, n, recsz;
	FILE *f;
	struct tls_rec *rec;
	struct tls_hand *hand;
	struct tls_shello *shello;
	struct tls_sess_id *sess;
	uint16_t *cipher;
	uint8_t *comp;
	struct tls_exts *exts;
	struct tls_ext *ext;
	struct tls_ext_key_share_entry *se;

	f = fopen("/tmp/shello", "rb");
	fread(b, 4096, 1, f);
	fclose(f);

	n = 0;
	rec = (struct tls_rec *)b + len;
	hand = (struct tls_hand *)&rec->data;
	shello = (struct tls_shello *)&hand->data;
	sess = (struct tls_sess_id *)&shello->data;

	rec->ver = ntohs(rec->ver);
	rec->len = ntohs(rec->len);
	printf("rt %x\n", rec->type);
	printf("rv %x\n", rec->ver);
	printf("rv %d\n", rec->len);
	recsz = sizeof(*rec) + rec->len;
	printf("rsz %d\n", recsz);
	n += sizeof(*rec);

	printf("ht %x\n", hand->type);
	hand->lenlo = ntohs(hand->lenlo);
	len = hand->lenhi;
	len <<= 16;
	len |= hand->lenlo;
	printf("hl %d\n", len);
	n += sizeof(*hand);

	shello->ver = ntohs(shello->ver);
	printf("sv %x\n", shello->ver);
	n += sizeof(*shello);

	printf("sl %d\n", sess->len);
	n += sizeof(*sess);
	n += sess->len;

	cipher = (uint16_t *)((char*)sess + sizeof(*sess) + sess->len);
	*cipher = ntohs(*cipher);
	printf("c %x\n", *cipher);
	n += sizeof(*cipher);

	comp = (uint8_t *)((char*)cipher + sizeof(*cipher));
	printf("cmp %d\n", *comp);
	n += sizeof(*comp);

	exts = (struct tls_exts *)((char*)comp + sizeof(*comp));
	exts->len = ntohs(exts->len);
	printf("es %d\n", exts->len);
	n += sizeof(*exts);

	ext = (struct tls_ext *)&exts->data;
	ext->type = ntohs(ext->type);
	ext->len = ntohs(ext->len);
	assert(ext->type == 43);
	n += sizeof(*ext) + ext->len;

	ext = (struct tls_ext *)((char*)ext + sizeof(*ext) + ext->len);
	ext->type = ntohs(ext->type);
	ext->len = ntohs(ext->len);
	assert(ext->type == 51);
	printf("et %x\n", ext->type);
	se = (struct tls_ext_key_share_entry *)&ext->data;
	se->group = ntohs(se->group);
	se->klen = ntohs(se->klen);
	assert(se->klen == 32);
	printf("klen %d\n", se->klen);
	/* convert to bigendian for our purposes. */
	for (i = 0; i < se->klen; ++i)
		peerpub[i] = se->key[se->klen - i - 1];
	n += sizeof(*ext) + ext->len;
	assert(n == recsz);
	return n;
	(void)buf;
}

int tls_fill_chello(uint8_t *buf, int len, const uint8_t *pubkey)
{
	int n, l;
	struct tls_rec *rec;
	struct tls_hand *hand;
	struct tls_chello *chello;
	struct tls_sess_id *sess;
	struct tls_ciphers *ciphers;
	struct tls_comp *comp;
	struct tls_exts *exts;
	struct tls_ext *ext;
	struct tls_ext_supported_groups *groups;
	struct tls_ext_sign_algos *algos;
	struct tls_ext_supported_vers *vers;
	struct tls_ext_ckey_share *shares;
	struct tls_ext_key_share_entry *se;

	n = 0;

	rec = (struct tls_rec *)buf;
	hand = (struct tls_hand *)&rec->data;
	chello = (struct tls_chello *)&hand->data;
	sess = (struct tls_sess_id *)&chello->data;

	rec->type = 0x16;
	rec->ver = 0x301;
	rec->len = 0;

	hand->type = 1;
	hand->lenhi = 0;
	hand->lenlo = 0;

	chello->ver = 0x303;
	rndm_fill(chello->rnd, 32 << 3);

	sess->len = 32;
	rndm_fill(sess->id, sess->len << 3);

	ciphers = (struct tls_ciphers *)((char*)sess + sizeof(*sess) +
					 sess->len);
	ciphers->len = 2;
	ciphers->ciphers[0] = htons(0x1303);

	comp = (struct tls_comp *)((char*)ciphers + sizeof(*ciphers) +
				   ciphers->len);
	comp->len = 1;
	comp->comp[0] = 0;





	exts = (struct tls_exts *)((char*)comp + sizeof(*comp) + comp->len);
	exts->len = 0;

	ext = (struct tls_ext *)&exts->data;
	ext->type = htons(10);
	groups = (struct tls_ext_supported_groups *)&ext->data;
	groups->len = htons(2);
	groups->groups[0] = htons(29);
	ext->len = sizeof(*groups) + ntohs(groups->len);
	n += sizeof(*ext) + ext->len;

	ext = (struct tls_ext *)((char*)ext + sizeof(*ext) + ext->len);
	ext->type = htons(13);
	algos = (struct tls_ext_sign_algos *)&ext->data;
	algos->len = htons(2);
	algos->algos[0] = htons(0x807);
	ext->len = sizeof(*algos) + ntohs(algos->len);
	n += sizeof(*ext) + ext->len;

	ext = (struct tls_ext *)((char*)ext + sizeof(*ext) + ext->len);
	ext->type = htons(43);
	vers = (struct tls_ext_supported_vers *)&ext->data;
	vers->len = 2;
	vers->vers[0] = htons(0x304);
	ext->len = sizeof(*vers) + vers->len;
	n += sizeof(*ext) + ext->len;

	ext = (struct tls_ext *)((char*)ext + sizeof(*ext) + ext->len);
	ext->type = htons(51);
	shares = (struct tls_ext_ckey_share *)&ext->data;
	se = (struct tls_ext_key_share_entry *)&shares->data;
	se->group = htons(29);
	se->klen = htons(32);
	memcpy(se->key, pubkey, 32);
	shares->len = htons(sizeof(*se) + ntohs(se->klen));
	ext->len = sizeof(*shares) + ntohs(shares->len);
	n += sizeof(*ext) + ext->len;

	exts->len = n;

	n += sizeof(*exts);
	n += sizeof(*comp) + comp->len;
	n += sizeof(*ciphers) + ciphers->len;
	n += sizeof(*sess) + sess->len;
	n += sizeof(*chello);
	hand->lenhi = n >> 16;
	hand->lenlo = n & 0xffff;

	n += sizeof(*hand);
	rec->len = n;

	n += sizeof(*rec);

	rec->ver = htons(rec->ver);
	rec->len = htons(rec->len);
	hand->lenlo = htons(hand->lenlo);
	chello->ver = htons(chello->ver);
	ciphers->len = htons(ciphers->len);
	exts->len = htons(exts->len);

	ext = (struct tls_ext *)&exts->data;
	l = ext->len;
	ext->len = htons(ext->len);

	ext = (struct tls_ext *)((char*)ext + sizeof(*ext) + l);
	l = ext->len;
	ext->len = htons(ext->len);

	ext = (struct tls_ext *)((char*)ext + sizeof(*ext) + l);
	l = ext->len;
	ext->len = htons(ext->len);

	ext = (struct tls_ext *)((char*)ext + sizeof(*ext) + l);
	ext->len = htons(ext->len);


	assert(n <= len);
	return n;
}
