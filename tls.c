/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <rndm.h>
#include <sha2.h>
#include <hkdf.h>
#include <sys/tls.h>

#if 0
static struct sha256_ctx transcript;
static uint8_t b[4096];
/*
 * Secret is assumed to be of size == hash's digest len.
 * The output length of expand is assumed to be the same.
 */
static void tls_derive_key(const void *secret, const char *label,
			   uint8_t *out)
{
	int i;
	uint16_t len;

	i = 0;
	len = htons(32);
	memcpy(b + i, &len, sizeof(len));
	i += sizeof(len);

	len = 6 + strlen(label);
	memcpy(b + i, &len, 1);
	++i;
	memcpy(b + i, "tls13 ", 6);
	i += 6;
	memcpy(b + i, label, strlen(label));
	i += strlen(label);

	len = 0;
	memcpy(b + i, &len, 1);
	++i;
	len = i;

	hkdf_sha256_expand(secret, SHA256_DIGEST_LEN, b, len, out,
			   32);
}

static void tls_derive_iv(const void *secret, const char *label,
			  uint8_t *out)
{
	int i;
	uint16_t len;

	i = 0;
	len = htons(8);
	memcpy(b + i, &len, sizeof(len));
	i += sizeof(len);

	len = 6 + strlen(label);
	memcpy(b + i, &len, 1);
	++i;
	memcpy(b + i, "tls13 ", 6);
	i += 6;
	memcpy(b + i, label, strlen(label));
	i += strlen(label);

	len = 0;
	memcpy(b + i, &len, 1);
	++i;
	len = i;

	hkdf_sha256_expand(secret, SHA256_DIGEST_LEN, b, len, out,
			   8);
}

static void tls_derive_secret(const void *secret, const char *label,
			      const void *msg, int mlen, uint8_t *out)
{
	int i;
	uint16_t len;

	i = 0;
	len = htons(SHA256_DIGEST_LEN);
	memcpy(b + i, &len, sizeof(len));
	i += sizeof(len);

	len = 6 + strlen(label);
	memcpy(b + i, &len, 1);
	++i;
	memcpy(b + i, "tls13 ", 6);
	i += 6;
	memcpy(b + i, label, strlen(label));
	i += strlen(label);

	len = SHA256_DIGEST_LEN;
	memcpy(b + i, &len, 1);
	++i;
	memcpy(b + i, msg, mlen);
	i += mlen;
	len = i;

	hkdf_sha256_expand(secret, SHA256_DIGEST_LEN, b, len, out,
			   SHA256_DIGEST_LEN);
}

// https://github.com/project-everest/ci-logs/blob/master/everest-test-10b31d91-20801.all
static const uint8_t sh[32] = {
	0x67,0x32,0x85,0x96,0x5d,0xfa,0x28,0xcd,
	0x80,0x2f,0x14,0x83,0x87,0x0a,0x1c,0xf7,
	0x2b,0x92,0x61,0x7b,0xc1,0xda,0x14,0xec,
	0x16,0xe4,0xd3,0x9b,0x6b,0xfa,0x24,0x72,
};

static const uint8_t zeroes[SHA256_DIGEST_LEN];
void tls_derive_keys(const void *shared, int slen)
{
	int i;
	uint8_t bytes[SHA256_DIGEST_LEN];
	uint8_t dgst[SHA256_DIGEST_LEN];
	(void)sh;

	/* Early Secret. */
	hkdf_sha256_extract(zeroes, sizeof(zeroes), zeroes, sizeof(zeroes),
			    bytes);

	/* Salt for next extract. */
	tls_derive_secret(bytes, "derived", NULL, 0, bytes);
	for (i = 0; i < 32; ++i)
		printf("%02x", bytes[i]);
	printf("\n");
	// https://tlswg.github.io/draft-ietf-tls-tls13-vectors/draft-ietf-tls-tls13-vectors.html#rfc.section.3

	/* Handshake Secret. */
	hkdf_sha256_extract(bytes, sizeof(bytes), shared, slen, bytes);
	for (i = 0; i < 32; ++i)
		printf("%02x", bytes[i]);
	printf("\n");

	sha256_final(&transcript, dgst);
	for (i = 0; i < 32; ++i)
		printf("%02x", dgst[i]);
	printf("\n");

	/* client handshake traffic secret. */
	tls_derive_secret(bytes, "c hs traffic", dgst, 32, bytes);
	for (i = 0; i < 32; ++i)
		printf("%02x", bytes[i]);
	printf("\n");
	/* server handshake traffic secret. */
	tls_derive_secret(bytes, "s hs traffic", dgst, 32, bytes);
	for (i = 0; i < 32; ++i)
		printf("%02x", bytes[i]);
	printf("\n");
	tls_derive_key(bytes, "key", dgst);
	for (i = 0; i < 32; ++i)
		printf("%02x", dgst[i]);
	printf("\n");
	tls_derive_iv(bytes, "iv", dgst);
	for (i = 0; i < 8; ++i)
		printf("%02x", dgst[i]);
	printf("\n");

	/*
	 * Derive the write and iv keys for both the directions, and apply
	 * them appropriately to the cipher.
	 */
	(void)shared;
	(void)slen;
}

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
	tls_deserialize(b, 4096);

	n = 0;
	rec = (struct tls_rec *)((char*)b + len);
	hand = (struct tls_hand *)&rec->data;
	shello = (struct tls_shello *)&hand->data;
	sess = (struct tls_sess_id *)&shello->data;


	rec->ver = ntohs(rec->ver);
	rec->len = ntohs(rec->len);
	printf("------------------\n");
	printf("rt %x\n", rec->type);
	printf("rv %x\n", rec->ver);
	printf("rl %d\n", rec->len);
	recsz = sizeof(*rec) + rec->len;
	printf("rsz %d\n", recsz);
	n += sizeof(*rec);
	if (rec->len == 1) //change cipher spec
		return 6;
	if (rec->len == 23) { //first cipher block
		return 0;
	}

	sha256_update(&transcript, hand, rec->len);

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
	(void)tls_derive_secret;
}
#endif

/* XXX: Allow a max of 8 extensions. */
void tls_deserialize_exts(const void *buf, size_t len,
			  struct tls_ext_sw sw[8])
{
	int i;
	const struct tls_ext_hw *hw;
	uint16_t v2;
	const uint8_t *p;
	hw = buf;

	for (i = 0; i < 8 && len; ++i) {
		sw[i].hw = *hw;
		sw[i].hw.type = ntohs(sw[i].hw.type);
		sw[i].hw.len = ntohs(sw[i].hw.len);
		p = (const uint8_t *)(hw + 1);

		switch (sw[i].hw.type) {
		case 43:
			/* Supported Version. */
			assert(sw[i].hw.len == 2);
			v2 = *(uint16_t *)p;
			*(uint16_t *)(&sw[i].data[0]) = ntohs(v2);
			assert(v2 == htons(0x304));
			break;
		default:
			printf("%s: unsup %x\n", __func__, sw[i].hw.type);
			assert(0);
		}
	}
}

void tls_deserialize_shello(const void *buf, size_t len,
			    struct tls_shello_sw *sw)
{
	const struct tls_shello_hw *hw;

	hw = buf;

	assert(hw->sess_len == 0);
	assert(hw->comp == 0);

	sw->hw = *hw;
	sw->hw.ver = ntohs(hw->ver);
	sw->hw.cipher = ntohs(hw->cipher);
	sw->hw.exts_len = ntohs(hw->exts_len);
	assert(sw->hw.exts_len >= 6);
	assert(sw->hw.exts_len <= len - sizeof(*hw));
	tls_deserialize_exts(hw + 1, len - sizeof(*hw), sw->exts);
}

void tls_deserialize_hand(const void *buf, size_t len, struct tls_hand_sw *sw)
{
	const struct tls_hand_hw *hw;
	hw = buf;
	sw->hw = *hw;
	sw->hw.lenlo = ntohs(hw->lenlo);
	switch (hw->type) {
	case TLS_HT_SHELLO:
		tls_deserialize_shello(hw + 1, len - sizeof(*hw),
				       &sw->u.shello);
		break;
	default:
		printf("%s: unsup %x\n", __func__, hw->type);
		assert(0);
	}
}

struct tls_rec_sw *tls_deserialize_rec(const void *buf, size_t len)
{
	size_t n;
	const struct tls_rec_hw *hw;
	struct tls_rec_sw *sw;

	assert(buf);
	/* Allow at least the size of a tls_rec. */
	assert(len >= sizeof(*hw));

	sw = malloc(sizeof(*sw));
	assert(sw);

	hw = buf;
	sw->hw = *hw;
	sw->hw.ver = ntohs(hw->ver);
	sw->hw.len = ntohs(hw->len);

	/* Sufficient input buffer size? */
	n = sizeof(*hw) + sw->hw.len;
	assert(len >= n);

	switch (hw->type) {
	case TLS_RT_HAND:
		tls_deserialize_hand(hw + 1, len - sizeof(*hw), &sw->u.hand);
		break;
	case TLS_RT_CIPHER:
		assert(sw->hw.len == 1);
		break;
	default:
		printf("%s: unsup %x\n", __func__, hw->type);
		assert(0);
	}
	return sw;
}

static void tls_serialize_exts(const struct tls_ext_sw sw[8], void *buf,
			       size_t len)
{
	int i;
	struct tls_ext_hw *hw;
	struct tls_kse_hw *khwi, *khwo;
	uint8_t *p;
	uint16_t a2;

	hw = buf;
	for (i = 0; i < 8; ++i) {
		if (sw[i].hw.type == (uint16_t)-1)
			break;
		*hw = sw[i].hw;
		hw->type = htons(hw->type);
		hw->len = htons(hw->len);
		p = (uint8_t *)(hw + 1);
		switch (sw[i].hw.type) {
		case 13:
			/* Signature Algorithms List. */
		case 10:
			/* Supported Groups List. */
			a2 = *(uint16_t *)(&sw[i].data[0]);
			assert(a2 == 2);	/* We support only 1. */
			*(uint16_t *)p = htons(a2);
			p += 2;

			a2 = *(uint16_t *)(&sw[i].data[2]);
			*(uint16_t *)p = htons(a2);
			break;
		case 43:
			/* Supported Versions List. */
			a2 = *(uint8_t *)(&sw[i].data[0]);
			assert(a2 == 2);	/* We support only 1. */
			*(uint8_t *)p = a2;
			++p;

			a2 = *(uint16_t *)(&sw[i].data[1]);
			*(uint16_t *)p = htons(a2);
			break;
		case 51:
			/* Key Share List. We support only 1. */
			a2 = *(uint16_t *)(&sw[i].data[0]);
			*(uint16_t *)p = htons(a2);
			p += 2;

			khwo = (struct tls_kse_hw *)p;
			khwi = (struct tls_kse_hw *)(&sw[i].data[2]);
			khwo->group = htons(khwi->group);
			khwo->klen = htons(khwi->klen);
			p += sizeof(*khwo);
			assert(khwi->klen == 32);
			memcpy(p, khwi + 1, khwi->klen);
			break;
		default:
			printf("%s: unsup %x\n", __func__, sw[i].hw.type);
			assert(0);
		}
		hw = (struct tls_ext_hw *)((char *)(hw + 1) + sw[i].hw.len);
	}
	(void)len;
}

static void tls_serialize_chello(const struct tls_chello_sw *sw, void *buf,
				 size_t len)
{
	struct tls_chello_hw *hw;
	hw = buf;
	*hw = sw->hw;
	hw->ver = htons(hw->ver);
	hw->cipher_len = htons(hw->cipher_len);
	hw->cipher = htons(hw->cipher);
	hw->exts_len = htons(hw->exts_len);
	tls_serialize_exts(sw->exts, hw + 1, len - sizeof(*hw));
}

static void tls_serialize_hand(const struct tls_hand_sw *sw, void *buf,
			       size_t len)
{
	struct tls_hand_hw *hw;
	hw = buf;
	*hw = sw->hw;
	hw->lenlo = htons(hw->lenlo);
	switch (hw->type) {
	case TLS_HT_CHELLO:
		tls_serialize_chello(&sw->u.chello, hw + 1, len - sizeof(*hw));
		break;
	default:
		printf("%s: unsup %x\n", __func__, hw->type);
		assert(0);
	}
}

static void tls_serialize_rec(const struct tls_rec_sw *sw, void *buf, size_t len)
{
	struct tls_rec_hw *hw;

	assert(buf);
	assert(len >= sw->hw.len + sizeof(sw->hw));

	hw = buf;
	*hw = sw->hw;
	hw->ver = htons(hw->ver);
	hw->len = htons(hw->len);
	switch (hw->type) {
	case TLS_RT_HAND:
		tls_serialize_hand(&sw->u.hand, hw + 1, len - sizeof(*hw));
		break;
	default:
		printf("%s: unsup type %x\n", __func__, hw->type);
		assert(0);
	}
}

/* pubkey must be 32 bytes in length. */
static int tls_new_chello(void *buf, int blen, const uint8_t *pubkey, int klen)
{
	int n;
	struct tls_rec_sw *rsw;
	struct tls_hand_sw *hsw;
	struct tls_chello_sw *chsw;
	struct tls_ext_sw *ext;
	struct tls_kse_hw *khw;

	rsw = malloc(sizeof(*rsw));
	assert(rsw);

	rsw->hw.type = TLS_RT_HAND;
	rsw->hw.ver = 0x303;

	hsw = &rsw->u.hand;
	hsw->hw.type = TLS_HT_CHELLO;

	chsw = &hsw->u.chello;
	memset(&chsw->hw.rnd, 0, 32);
	//rndm_fill(&chsw->hw.rnd, 32 << 3);
	chsw->hw.ver = 0x303;
	chsw->hw.sess_len = 0;
	chsw->hw.cipher_len = 2;
	chsw->hw.cipher = 0x1303;
	chsw->hw.comp_len = 1;
	chsw->hw.comp = 0;
	chsw->hw.exts_len = 0;

	/* Supported Groups List. */
	ext = &chsw->exts[0];
	ext->hw.type = 10;
	*(uint16_t *)(&ext->data[0]) = 2;
	*(uint16_t *)(&ext->data[2]) = 29;
	ext->hw.len = 4;
	chsw->hw.exts_len += ext->hw.len;

	/* Signature Algorithms List. */
	ext = &chsw->exts[1];
	ext->hw.type = 13;
	*(uint16_t *)(&ext->data[0]) = 2;
	*(uint16_t *)(&ext->data[2]) = 0x807;
	ext->hw.len = 4;
	chsw->hw.exts_len += ext->hw.len;

	/* Supported Versions List. */
	ext = &chsw->exts[2];
	ext->hw.type = 43;
	*(uint8_t *)(&ext->data[0]) = 2;
	*(uint16_t *)(&ext->data[1]) = 0x304;
	ext->hw.len = 3;
	chsw->hw.exts_len += ext->hw.len;

	/* Key Share List. */
	assert(klen == 32);
	ext = &chsw->exts[3];
	ext->hw.type = 51;
	/* Client key share length. */
	*(uint16_t *)(&ext->data[0]) = sizeof(*khw) + klen;
	khw = (struct tls_kse_hw *)(&ext->data[2]);
	khw->group = 29;
	khw->klen = klen;
	memcpy(khw + 1, pubkey, klen);
	ext->hw.len = sizeof(*khw) + klen + 2;
	chsw->hw.exts_len += ext->hw.len;

	/* Software end. Used by serializer. */
	ext = &chsw->exts[4];
	ext->hw.type = -1;

	chsw->hw.exts_len += 4 * sizeof(struct tls_ext_hw);
	n = chsw->hw.exts_len + sizeof(chsw->hw);
	hsw->hw.lenhi = n >> 16;
	hsw->hw.lenlo = n & 0xffff;
	rsw->hw.len = n + sizeof(hsw->hw);
	n = rsw->hw.len + sizeof(rsw->hw);
	tls_serialize_rec(rsw, buf, blen);
	return n;
}

struct tls_cli_ctx *tls_cli_new(const uint8_t *pubkey, int klen)
{
	struct tls_cli_ctx *ctx;

	assert(klen == 32);	/* For now. */
	ctx = malloc(sizeof(*ctx));
	assert(ctx);

	ctx->pubkey = malloc(klen);
	assert(ctx->pubkey);

	memcpy(ctx->pubkey, pubkey, klen);
	ctx->klen = klen;
	ctx->state = 0;
	return ctx;
}

int tls_cli_connect(struct tls_cli_ctx *ctx, const char *ip, short port)
{
	int n, sock, len;
	uint8_t *buf;
	FILE *f;
	struct sockaddr_in srvr = {0};
	struct tls_rec_sw *sw;

	buf = malloc(4096);
	assert(buf);
	n = tls_new_chello(buf, 4096, ctx->pubkey, ctx->klen);
	ctx->chello = malloc(n);
	assert(ctx->chello);
	memcpy(ctx->chello, buf, n);
	goto parse;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	srvr.sin_family = AF_INET;
	srvr.sin_port = htons((short)port);
	inet_pton(AF_INET, ip, &srvr.sin_addr);
	connect(sock, (const struct sockaddr *)&srvr, sizeof(srvr));
	send(sock, buf, n, 0);
	n = recv(sock, buf, 4096, 0);
	printf("recvd %d\n", n);
	close(sock);

	f = fopen("/tmp/shello", "wb");
	fwrite(buf, 1, n, f);
	fclose(f);
parse:
	f = fopen("/tmp/shello", "rb");
	n = fread(buf, 1, 4096, f);
	fclose(f);

	len = n;
	for (;len;) {
		printf("aaa\n");
		sw = tls_deserialize_rec(buf, len);
		n = sw->hw.len + sizeof(sw->hw);
		if (sw->hw.type == TLS_RT_HAND &&
		    sw->u.hand.hw.type == TLS_HT_SHELLO) {
			ctx->shello = malloc(n);
			assert(ctx->shello);
			memcpy(ctx->shello, buf, n);
		}
		len -= n;
		buf += n;
		free(sw);
	}

	return 0;
}
