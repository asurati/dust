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

#include <bn.h>
#include <ec.h>
#include <rndm.h>
#include <sha2.h>
#include <hkdf.h>
#include <chacha.h>
#include <aead.h>

#include <sys/tls.h>

/* Numbers as big-endian strings. */
const char *c25519_prime	=
"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed";
const char *c25519_a		= "76d06";	// hex(486662)
const char *c25519_b		= "1";
const char *c25519_gx		= "9";
const char *c25519_order	=
"1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed";

/* Numbers as big-endian strings. */
const char *priv_str	=
"59effe2eb776d8e7118dda26b46cce413bfa0e2d4993acabaae91cf16c8c7d28";
const char *pub_str	=
"671e3b404cd8512b5077822a2e7764d614cdda6f67d3c6433ce63d5bcb132b7d";

static void tls_hkdf_expand_label(const void *secret, const char *label,
				  const void *thash, uint8_t *out, int olen)
{
	int i, n;
	uint16_t len;
	uint8_t info[514];

	i = 0;

	len = htons(olen);
	*(uint16_t *)info = len;
	i += sizeof(len);

	n = strlen(label);
	assert(n > 0 && n <= 12);
	len = 6 + n;
	*(uint8_t *)(&info[i]) = (uint8_t)len;
	++i;
	memcpy(&info[i], "tls13 ", 6);
	i += 6;
	memcpy(&info[i], label, n);
	i += n;

	if (thash)
		len = SHA256_DIGEST_LEN;
	else
		len = 0;
	memcpy(&info[i], &len, 1);
	++i;
	if (thash)
		memcpy(&info[i], thash, len);
	i += len;
	len = i;

	hkdf_sha256_expand(secret, SHA256_DIGEST_LEN, info, len, out, olen);
}

/*
 * Derive-Secret's secret is the output of HKDF-extract. The size ==
 * size of the output of the hash function.
 *
 * thash == Transcript Hash. Its size == size of the Hash function's
 * output.
 *
 * out's size is also the same.
 */
static void tls_derive_secret(const void *secret, const char *label,
			      const void *thash, uint8_t *out)
{
	tls_hkdf_expand_label(secret, label, thash, out, SHA256_DIGEST_LEN);
}

// https://github.com/project-everest/ci-logs/blob/master/everest-test-10b31d91-20801.all
void tls_derive_keys(struct tls_ctx *ctx)
{
	int i, n;
	uint8_t dgst[SHA256_DIGEST_LEN];
	struct sha256_ctx hctx;
	struct ec *ec;
	struct ec_point *pub;
	struct bn *t, *priv;
	struct ec_mont_params emp;

	emp.prime	= c25519_prime;
	emp.a		= c25519_a;
	emp.b		= c25519_b;
	emp.gx		= c25519_gx;
	emp.order	= c25519_order;

	ec = ec_new_montgomery(&emp);
	priv = bn_new_from_bytes_le(ctx->priv, ctx->klen);

	/*
	 * Server's x25519 key share arrives in the little-endian byte-array
	 * form on the network.
	 */
	t = bn_new_from_bytes_le(ctx->pub[1], ctx->klen);
	bn_print("pub:", t);
	pub = ec_point_new(ec, t, NULL, NULL);
	ec_scale(ec, pub, priv);
	bn_free(priv);
	bn_free(t);
	t = ec_point_x(ec, pub);

	/*
	 * Shared secret needs to be converted to little-endian byte-array
	 * before utilizing.
	 */
	ctx->shared = bn_to_bytes_le(t, &n);
	assert(n == ctx->klen);
	bn_free(t);
	ec_point_free(ec, pub);
	ec_free(ec);

	memset(dgst, 0, sizeof(dgst));

	/* Early Secret. */
	hkdf_sha256_extract(NULL, 0, dgst, sizeof(dgst), ctx->es);
	/* 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a */
	printf("early:");
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", ctx->es[i]);
	printf("\n");

	/*
	 * Salt for ECDHE extract. Transcript sent is empty. So thash is the
	 * hash of the empty string. The result can be used as it is.
	 */
	sha256_init(&hctx);
	sha256_final(&hctx, dgst);
	tls_derive_secret(ctx->es, "derived", dgst, dgst);
	/* 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba */
	printf("ecdhe salt:");
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", dgst[i]);
	printf("\n");

	/* ECDHE extract == Handshake secret. Can be used as it is. */
	hkdf_sha256_extract(dgst, sizeof(dgst), ctx->shared, ctx->klen,
			    ctx->hs);
	printf("hs:");
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", ctx->hs[i]);
	printf("\n");

	/* Client/Server handshake traffic secrets. */
	n = sizeof(struct tls_rec_hw);
	sha256_init(&hctx);
	sha256_update(&hctx, (char *)ctx->chello + n, ctx->chello_len - n);
	sha256_update(&hctx, (char *)ctx->shello + n, ctx->shello_len - n);
	sha256_final(&hctx, dgst);
	/* The hash of the transcript. Use as it is. */

	tls_derive_secret(ctx->hs, "c hs traffic", dgst, ctx->chts);
	printf("chts:");
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", ctx->chts[i]);
	printf("\n");
	tls_derive_secret(ctx->hs, "s hs traffic", dgst, ctx->shts);
	printf("shts:");
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", ctx->shts[i]);
	printf("\n");
	return;
}

/* XXX: Allow a max of 8 extensions. */
void tls_deserialize_exts(const void *buf, size_t len,
			  struct tls_ext_sw sw[8])
{
	int i, n;
	const struct tls_ext_hw *hw;
	struct tls_kse_hw *khwo;
	const struct tls_kse_hw *khwi;
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
		case 51:
			/* Key Share. */
			khwi = (struct tls_kse_hw *)p;
			khwo = (struct tls_kse_hw *)(&sw[i].data[0]);
			khwo->group = ntohs(khwi->group);
			khwo->klen = ntohs(khwi->klen);
			p += sizeof(*khwo);
			assert(khwo->klen == 32);
			memcpy(khwo + 1, p, khwo->klen);
			break;
		default:
			printf("%s: unsup %x\n", __func__, sw[i].hw.type);
			assert(0);
		}
		n = sizeof(sw[i].hw) + sw[i].hw.len;
		len -= n;
		hw = (struct tls_ext_hw *)((char *)hw + n);
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
	tls_deserialize_exts(hw + 1, sw->hw.exts_len, sw->exts);
}

void tls_deserialize_hand(const void *buf, size_t len, struct tls_hand_sw *sw)
{
	int n;
	const struct tls_hand_hw *hw;

	hw = buf;
	sw->hw = *hw;
	sw->hw.lenlo = ntohs(hw->lenlo);
	n  = sw->hw.lenhi << 16;
	n |= sw->hw.lenlo;
	switch (hw->type) {
	case TLS_HT_SHELLO:
		tls_deserialize_shello(hw + 1, n, &sw->u.shello);
		break;
	default:
		printf("%s: unsup %x\n", __func__, hw->type);
		assert(0);
	}
	(void)len;
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
		tls_deserialize_hand(hw + 1, sw->hw.len, &sw->u.hand);
		break;
	case TLS_RT_CIPHER:
		assert(sw->hw.len == 1);
		break;
	case TLS_RT_DATA:
		memcpy(sw->u.data, hw + 1, sw->hw.len);
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

struct tls_ctx *tls_ctx_new()
{
	int n;
	struct tls_ctx *ctx;
	struct ec *ec;
	struct ec_point *pub;
	struct bn *t, *priv;
	struct ec_mont_params emp;

	emp.prime	= c25519_prime;
	emp.a		= c25519_a;
	emp.b		= c25519_b;
	emp.gx		= c25519_gx;
	emp.order	= c25519_order;

	ctx = malloc(sizeof(*ctx));
	assert(ctx);

	ctx->klen = 32;
	ctx->state = 0;

	priv = bn_new_from_string_be(priv_str, 16);
	ctx->priv = bn_to_bytes_le(priv, &n);
	assert(n == 32);

	ec = ec_new_montgomery(&emp);
	pub = ec_gen_public(ec, priv);
	t = ec_point_x(ec, pub);
	/* On-Wire format is little-endian byte array. */
	ctx->pub[0] = bn_to_bytes_le(t, &n);
	assert(n == 32);

	bn_free(t);
	ec_point_free(ec, pub);
	ec_free(ec);
	bn_free(priv);
	return ctx;
}

/*
     X25519 Private-Key:
     priv:
         20:f7:bc:24:6f:dd:be:70:10:7c:40:18:9b:06:ff:
         27:79:77:32:27:2c:1b:f0:a9:15:79:e6:62:48:00:
         09:49
     pub:
         e3:3a:59:4b:e6:fb:29:bb:41:45:77:16:5b:b8:e5:
         80:2b:71:a0:fc:9d:45:c0:6a:27:89:45:27:57:61:
         70:0e
key:05fdd51e726270430fc321267a4d5683a4572b6867a478c20f608df050e026f4
iv:c9367e4bbab227886e468c23
key:b6dc4f6da0805f0751770d6a71402b1fa831d43b81f70c471d9d89bad9c07635
iv:ba5071ad55548d42c6d08300
key:9967fca75d10bfc07052161d8c5dbd7ba1674e5ef53f92d5bd86b56203bc30b8
iv:d08a974ece193316e0d9c24e
*/

static void tls_decipher_data(struct tls_ctx *ctx, const struct tls_rec_hw *hw,
			      uint8_t *buf, size_t len)
{
	int i;
	uint8_t data[60];
	uint8_t key[32];
	uint8_t iv[12];
	struct tls_rec_hw rhw;
	static int sequence = 0;

	tls_hkdf_expand_label(ctx->shts, "key", NULL, key, 32);
	tls_hkdf_expand_label(ctx->shts, "iv", NULL, iv, 12);
	printf("key:");
	for (i = 0; i < 32; ++i)
		printf("%02x", key[i]);
	printf("\n");
	printf("iv:");
	for (i = 0; i < 12; ++i)
		printf("%02x", iv[i]);
	printf("\n");

	rhw = *hw;
	rhw.ver = htons(rhw.ver);
	rhw.len = htons(rhw.len);
	iv[11] ^= sequence++;

	assert(sizeof(*hw) == 5);
	aead_dec(key, iv, buf, len, &rhw, sizeof(rhw), data);
	for (i = 0; i < (int)len - 16; ++i)
		printf("%02x ", data[i]);
	printf("\n");
}

int tls_connect(struct tls_ctx *ctx, const char *ip, short port)
{
	int n, sock, len, i;
	uint8_t *buf;
	FILE *f;
	struct sockaddr_in srvr = {0};
	struct tls_rec_sw *sw;
	struct tls_ext_sw *ext;
	struct tls_kse_hw *khw;

	buf = malloc(4096);
	assert(buf);
	n = tls_new_chello(buf, 4096, ctx->pub[0], ctx->klen);
	ctx->chello = malloc(n);
	ctx->chello_len = n;
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
	goto parse;
parse:
	f = fopen("/tmp/shello", "rb");
	n = fread(buf, 1, 4096, f);
	fclose(f);

	len = n;
	for (;len;) {
		sw = tls_deserialize_rec(buf, len);
		n = sw->hw.len + sizeof(sw->hw);
		if (sw->hw.type == TLS_RT_DATA) {
			tls_decipher_data(ctx, &sw->hw, sw->u.data,
					  sw->hw.len);
		}

		if (sw->hw.type == TLS_RT_HAND &&
		    sw->u.hand.hw.type == TLS_HT_SHELLO) {
			ctx->shello = malloc(n);
			ctx->shello_len = n;
			assert(ctx->shello);
			memcpy(ctx->shello, buf, n);
			/* Find the key share of the server */
			for (i = 0; i < 8; ++i) {
				ext = &sw->u.hand.u.shello.exts[i];
				khw = (struct tls_kse_hw *)&ext->data[0];
				if (ext->hw.type == 51) {
					assert(khw->klen == 32);
					ctx->pub[1] = (uint8_t*)(khw + 1);
					break;
				}
			}
			assert(i < 8);
			tls_derive_keys(ctx);
		}
		len -= n;
		buf += n;
		free(sw);
	}

	return 0;
}

//https://tlswg.github.io/draft-ietf-tls-tls13-vectors/draft-ietf-tls-tls13-vectors.html#rfc.section.3
const char *chello_str=
"01 00 00 c0 03 03 66 60 26 1f f9 47 ce a4 9c ce 6c fa d6 87 f4 57 cf 1b 14 53 1b a1 41 31 a0 e8 f3 09 a1 d0 b9 c4 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 4c fd fc d1 78 b7 84 bf 32 8c ae 79 3b 13 6f 2a ed ce 00 5f f1 83 d7 bb 14 95 20 72 36 64 70 37 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

const char *shello_str=
"02 00 00 56 03 03 12 74 99 14 95 cf 42 58 57 26 2d de 22 99 34 2c 31 5a fb a9 b6 4a 87 d5 52 51 56 14 e0 1b 04 5d 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c7 bb 6b df c2 63 50 b9 29 a0 8a 41 a7 6d da c2 10 b0 96 86 8d 96 0c 48 45 98 7d c3 a7 fa 65 0a 00 2b 00 02 03 04";

const char *cli_priv_le = "70 a1 a8 f4 91 e8 2d 53 05 42 c6 d7 a8 dc d8 cf a9 e3 1f 59 bb 33 6b 55 0b 13 bf e1 99 f5 42 45";
const char *srv_pub_le = "c7 bb 6b df c2 63 50 b9 29 a0 8a 41 a7 6d da c2 10 b0 96 86 8d 96 0c 48 45 98 7d c3 a7 fa 65 0a";

const char *salt_str = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
void tls_test()
{
	int i, n, len;
	uint8_t dgst[SHA256_DIGEST_LEN];
	uint8_t hs[SHA256_DIGEST_LEN];
	struct sha256_ctx hctx;
	struct ec *ec;
	struct ec_point *pub[2];
	struct bn *t, *priv;
	struct ec_mont_params emp;
	uint8_t *buf, *salt, *shared;
	uint8_t key[32];
	uint8_t iv[12];

	emp.prime	= c25519_prime;
	emp.a		= c25519_a;
	emp.b		= c25519_b;
	emp.gx		= c25519_gx;
	emp.order	= c25519_order;

	ec = ec_new_montgomery(&emp);

	priv = bn_new_from_string_le(cli_priv_le, 16);
	//bn_print("", priv);

	pub[0] = ec_gen_public(ec, priv);
	//ec_point_print(ec, pub[0]);

	/*
	 * Server's x25519 key share arrives in the little-endian byte-array
	 * form on the network.
	 */
	t = bn_new_from_string_le(srv_pub_le, 16);
	bn_print("pub1: ", t);
	pub[1] = ec_point_new(ec, t, NULL, NULL);
	bn_free(t);
	ec_scale(ec, pub[1], priv);
	ec_point_print(ec, pub[1]);

	/*
	 * ECHDE salt is calculated through the key schedule. We have it
	 * pre-saved in a big-endian string form. The byte-array should
	 * contain the salt in a big-endian form, as this was calculated
	 * by sha256, a big-endian hash.
	 */
	t = bn_new_from_string_be(salt_str, 16);
	salt = bn_to_bytes_be(t, &n);
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", salt[i]);
	printf("\n");
	bn_free(t);

	/*
	 * The shared secret. Needs to be converted into little-endian
	 * byte array before processing.
	 */
	t = ec_point_x(ec, pub[1]);
	bn_print("", t);
	shared = bn_to_bytes_le(t, &n);
	hkdf_sha256_extract(salt, 32, shared, 32, hs);
	/*
	 * The digest is in big-endian form, as required. The hkdf needs
	 * their inputs in little-endian array, but their outputs can be
	 * used as they are.
	 */
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", hs[i]);
	printf("\n");
	bn_free(t);


	sha256_init(&hctx);
	t = bn_new_from_string_be(chello_str, 16);
	shared = bn_to_bytes_be(t, &n);
	printf("%d\n", n);
	sha256_update(&hctx, shared, n);
	t = bn_new_from_string_be(shello_str, 16);
	shared = bn_to_bytes_be(t, &n);
	printf("%d\n", n);
	sha256_update(&hctx, shared, n);
	sha256_final(&hctx, dgst);
	/* Again, dgst from sha256 can be used as it is. */

	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", dgst[i]);
	printf("\n");

	//tls_derive_secret(hs, "c hs traffic", dgst, dgst);
	/* The output again is hkdf's. So can be used as it is. */
	//for (i = 0; i < SHA256_DIGEST_LEN; ++i)
	//	printf("%02x", dgst[i]);
	//printf("\n");

	tls_derive_secret(hs, "s hs traffic", dgst, dgst);
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", dgst[i]);
	printf("\n");

	memcpy(hs, dgst, sizeof(dgst));

	tls_hkdf_expand_label(hs, "key", NULL, key, 32);
	tls_hkdf_expand_label(hs, "iv", NULL, iv, 12);
	for (i = 0; i < 16; ++i)
		printf("%02x", key[i]);
	printf("\n");



	ec_point_free(ec, pub[0]);
	ec_point_free(ec, pub[1]);
	bn_free(priv);
	bn_free(t);

	assert(0);
	(void)n;
	(void)key;
	(void)len;
	(void)buf;
	(void)dgst;
}

