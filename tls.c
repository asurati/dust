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
#include <endian.h>

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
	uint8_t len8;
	static uint8_t info[514];

	/*
	 * Store 1-byte lengths in a uint8_t.
	 * Avoids endianness problems when passing len instead.
	 */
	i = 0;

	len = htons(olen);
	*(uint16_t *)info = len;
	i += sizeof(len);

	n = strlen(label);
	assert(n > 0 && n <= 12);
	len8 = 6 + n;
	*(uint8_t *)(&info[i]) = len8;
	++i;
	memcpy(&info[i], "tls13 ", 6);
	i += 6;
	memcpy(&info[i], label, n);
	i += n;

	if (thash)
		len8 = SHA256_DIGEST_LEN;
	else
		len8 = 0;
	memcpy(&info[i], &len8, 1);
	++i;
	if (thash)
		memcpy(&info[i], thash, len8);
	i += len8;

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

/* XXX: Allow a max of 8 extensions. */
void tls_deserialize_exts(struct tls_ctx *ctx, struct tls_ext_sw sw[8],
			  const void *buf, int len)
{
	int i, n;
	const struct tls_ext_hw *hw;
	struct tls_kse_hw *khwo;
	const struct tls_kse_hw *khwi;
	uint16_t v2;
	const uint8_t *p;

	/* TODO length verification. */
	hw = buf;
	for (i = 0; i < 8 && len > 0; ++i) {
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
			ctx->secrets.pub[1] = malloc(khwo->klen);
			assert(ctx->secrets.pub[1]);
			memcpy(ctx->secrets.pub[1], p, khwo->klen);
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

void tls_deserialize_shello(struct tls_ctx *ctx, struct tls_shello_sw *sw,
			    const void *buf, int len)
{
	const struct tls_shello_hw *hw;

	hw = buf;

	/* Only TLSv1.3 support. */
	assert(hw->sess_len == 0);
	assert(hw->comp == 0);

	sw->hw = *hw;
	sw->hw.ver = ntohs(hw->ver);
	sw->hw.cipher = ntohs(hw->cipher);
	sw->hw.exts_len = ntohs(hw->exts_len);
	assert(sw->hw.exts_len >= 6);	/* RFC. */
	assert(len == sw->hw.exts_len + (int)sizeof(*hw));
	tls_deserialize_exts(ctx, sw->exts, hw + 1, sw->hw.exts_len);
}

void tls_deserialize_encexts(struct tls_ctx *ctx, struct tls_encext_sw *sw,
			     const void *buf, int len)
{
	const struct tls_encext_hw *hw;

	(void)ctx;
	(void)len;

	hw = buf;

	sw->hw = *hw;
	sw->hw.exts_len = ntohs(hw->exts_len);

	/* We support no encrypted extensions yet. */
	assert(sw->hw.exts_len == 0);
}

void tls_deserialize_hand(struct tls_ctx *ctx, struct tls_hand_sw *sw,
			  const void *buf, int len)
{
	int n;
	const struct tls_hand_hw *hw;

	hw = buf;
	sw->hw = *hw;
	sw->hw.lenlo = ntohs(hw->lenlo);
	n  = sw->hw.lenhi << 16;
	n |= sw->hw.lenlo;
	assert (len == n + (int)sizeof(*hw));

	switch (hw->type) {
	case TLS_HT_SHELLO:
		tls_deserialize_shello(ctx, &sw->u.shello, hw + 1, n);
		break;
	case TLS_HT_ENCEXT:
		tls_deserialize_encexts(ctx, &sw->u.encext, hw + 1, n);
		break;
	case TLS_HT_CERT:
		printf("%s: unsup CERT\n", __func__);
		break;
	case TLS_HT_CV:
		printf("%s: unsup CV\n", __func__);
		break;
	case TLS_HT_FIN:
		printf("%s: unsup FIN\n", __func__);
		break;
	default:
		printf("%s: unsup %x\n", __func__, hw->type);
		assert(0);
	}
}

struct tls_rec_sw *tls_deserialize_rec(struct tls_ctx *ctx, const void *buf,
				       int len)
{
	const struct tls_rec_hw *hw;
	struct tls_rec_sw *sw;

	sw = malloc(sizeof(*sw));
	assert(sw);

	hw = buf;
	sw->hw = *hw;
	sw->hw.ver = ntohs(hw->ver);
	sw->hw.len = ntohs(hw->len);

	/* Proper input buffer size? */
	assert(len == (int)sizeof(*hw) + sw->hw.len);

	switch (hw->type) {
	case TLS_RT_HAND:
		tls_deserialize_hand(ctx, &sw->u.hand, hw + 1, sw->hw.len);
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

static void tls_serialize_exts(void *buf, int len,
			       const struct tls_ext_sw sw[8])
{
	int i;
	struct tls_ext_hw *hw;
	struct tls_kse_hw *khwi, *khwo;
	uint8_t *p;
	uint16_t v2;

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
			v2 = *(uint16_t *)(&sw[i].data[0]);
			assert(v2 == 2);	/* We support only 1. */
			*(uint16_t *)p = htons(v2);
			p += 2;

			v2 = *(uint16_t *)(&sw[i].data[2]);
			*(uint16_t *)p = htons(v2);
			break;
		case 43:
			/* Supported Versions List. */
			v2 = *(uint8_t *)(&sw[i].data[0]);
			assert(v2 == 2);	/* We support only 1. */
			*(uint8_t *)p = v2;
			++p;

			v2 = *(uint16_t *)(&sw[i].data[1]);
			*(uint16_t *)p = htons(v2);
			break;
		case 51:
			/* Key Share List. We support only 1. */
			v2 = *(uint16_t *)(&sw[i].data[0]);
			*(uint16_t *)p = htons(v2);
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

static void tls_serialize_chello(void *buf, int len,
				 const struct tls_chello_sw *sw)
{
	struct tls_chello_hw *hw;

	hw = buf;
	*hw = sw->hw;
	hw->ver = htons(hw->ver);
	hw->cipher_len = htons(hw->cipher_len);
	hw->cipher = htons(hw->cipher);
	hw->exts_len = htons(hw->exts_len);
	tls_serialize_exts(hw + 1, len - sizeof(*hw), sw->exts);
}

static void tls_serialize_hand(void *buf, int len,
			       const struct tls_hand_sw *sw)
{
	struct tls_hand_hw *hw;

	hw = buf;
	*hw = sw->hw;
	hw->lenlo = htons(hw->lenlo);
	switch (hw->type) {
	case TLS_HT_CHELLO:
		tls_serialize_chello(hw + 1, len - sizeof(*hw), &sw->u.chello);
		break;
	default:
		printf("%s: unsup %x\n", __func__, hw->type);
		assert(0);
	}
}

static void tls_serialize_rec(void *buf, int len,
			      const struct tls_rec_sw *sw)
{
	struct tls_rec_hw *hw;

	hw = buf;
	*hw = sw->hw;
	hw->ver = htons(hw->ver);
	hw->len = htons(hw->len);
	switch (hw->type) {
	case TLS_RT_HAND:
		tls_serialize_hand(hw + 1, len - sizeof(*hw), &sw->u.hand);
		break;
	default:
		printf("%s: unsup type %x\n", __func__, hw->type);
		assert(0);
	}
}

static struct tls_rec_sw *tls_new_chello(const struct tls_ctx *ctx)
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
	rsw->hw.ver = TLS_12;

	hsw = &rsw->u.hand;
	hsw->hw.type = TLS_HT_CHELLO;

	chsw = &hsw->u.chello;
	memset(&chsw->hw.rnd, 0, 32);
	//rndm_fill(&chsw->hw.rnd, 32 << 3);
	chsw->hw.ver = TLS_12;
	chsw->hw.sess_len = 0;
	chsw->hw.cipher_len = 2;
	chsw->hw.cipher = 0x1303;	/* TLS_CHACHA20_POLY1305_SHA256. */
	chsw->hw.comp_len = 1;
	chsw->hw.comp = 0;
	chsw->hw.exts_len = 0;

	/* Supported Groups List. */
	ext = &chsw->exts[0];
	ext->hw.type = 10;
	*(uint16_t *)(&ext->data[0]) = 2;
	*(uint16_t *)(&ext->data[2]) = 29;	/* X25519 */
	ext->hw.len = 4;
	chsw->hw.exts_len += ext->hw.len;

	/* Signature Algorithms List. */
	ext = &chsw->exts[1];
	ext->hw.type = 13;
	*(uint16_t *)(&ext->data[0]) = 2;
	*(uint16_t *)(&ext->data[2]) = 0x807;	/* Ed25519 */
	ext->hw.len = 4;
	chsw->hw.exts_len += ext->hw.len;

	/* Supported Versions List. */
	ext = &chsw->exts[2];
	ext->hw.type = 43;
	*(uint8_t *)(&ext->data[0]) = 2;
	*(uint16_t *)(&ext->data[1]) = 0x304;	/* TLSv1.3 */
	ext->hw.len = 3;
	chsw->hw.exts_len += ext->hw.len;

	/* Key Share List. */
	ext = &chsw->exts[3];
	ext->hw.type = 51;
	/* Client key share length. */
	*(uint16_t *)(&ext->data[0]) = sizeof(*khw) + 32;
	khw = (struct tls_kse_hw *)(&ext->data[2]);
	khw->group = 29;	/* X25519. */
	khw->klen = 32;
	memcpy(khw + 1, ctx->secrets.pub[0], 32);
	ext->hw.len = sizeof(*khw) + 32 + 2;
	chsw->hw.exts_len += ext->hw.len;

	/* Software end. Used by the serializer. */
	ext = &chsw->exts[4];
	ext->hw.type = -1;

	/* Fill in various lengths from bottom up. */
	chsw->hw.exts_len += 4 * sizeof(struct tls_ext_hw);
	n = chsw->hw.exts_len + sizeof(chsw->hw);
	hsw->hw.lenhi = n >> 16;
	hsw->hw.lenlo = n & 0xffff;
	rsw->hw.len = n + sizeof(hsw->hw);
	return rsw;
}

struct tls_ctx *tls_ctx_new()
{
	int n;
	struct tls_ctx *ctx;
	struct ec *ec;
	struct ec_point *pub;
	struct bn *t, *priv;
	struct ec_mont_params emp;
	struct sha256_ctx hctx;

	emp.prime	= c25519_prime;
	emp.a		= c25519_a;
	emp.b		= c25519_b;
	emp.gx		= c25519_gx;
	emp.order	= c25519_order;

	ctx = malloc(sizeof(*ctx));
	assert(ctx);

	ctx->role = TLS_CLIENT;
#if 0
	ctx->klen = 32;	/* For the fixed ECDHE group X25519. */
#endif

	priv = bn_new_from_string_be(priv_str, 16);
	ctx->secrets.priv = bn_to_bytes_le(priv, &n);
	assert(n == 32);

	ec = ec_new_montgomery(&emp);
	pub = ec_gen_public(ec, priv);
	t = ec_point_x(ec, pub);
	/* On-Wire format is little-endian byte array. */
	ctx->secrets.pub[0] = bn_to_bytes_le(t, &n);	/* My public. */

	sha256_init(&hctx);
	sha256_final(&hctx, ctx->transcript.empty);

	bn_free(t);
	ec_point_free(ec, pub);
	ec_free(ec);
	bn_free(priv);
	return ctx;
}

static void tls_derive_handshake_secrets(struct tls_ctx *ctx,
					 const void *shello, int len)
{
	int sz;
	uint8_t *p;
	struct sha256_ctx hctx;
	static uint8_t dgst[SHA256_DIGEST_LEN];
	struct ec *ec;
	struct ec_point *pub;
	struct bn *t, *priv;
	struct ec_mont_params emp;

	/* Update the running transcript hash. */
	sz = sizeof(struct tls_rec_hw);
	hctx = ctx->transcript.hctx;
	sha256_update(&hctx, (const uint8_t*)shello + sz, len - sz);
	ctx->transcript.hctx = hctx;
	sha256_final(&hctx, ctx->transcript.shello);

	/* Calculate the ECDHE shared secret. */
	emp.prime	= c25519_prime;
	emp.a		= c25519_a;
	emp.b		= c25519_b;
	emp.gx		= c25519_gx;
	emp.order	= c25519_order;

	ec = ec_new_montgomery(&emp);
	priv = bn_new_from_bytes_le(ctx->secrets.priv, 32);

	/*
	 * Server's x25519 key share arrives in the little-endian byte-array
	 * form on the network.
	 */
	t = bn_new_from_bytes_le(ctx->secrets.pub[1], 32);
	pub = ec_point_new(ec, t, NULL, NULL);
	ec_scale(ec, pub, priv);
	bn_free(priv);
	bn_free(t);
	t = ec_point_x(ec, pub);

	/*
	 * Shared secret needs to be converted to little-endian byte-array
	 * before utilizing.
	 */
	ctx->secrets.shared = bn_to_bytes_le(t, &sz);
	assert(sz == 32);
	bn_free(t);
	ec_point_free(ec, pub);
	ec_free(ec);

	/*
	 * Salt for ECDHE extract. Transcript sent is empty. So thash is the
	 * hash of the empty string. The result can be used as it is.
	 */
	tls_derive_secret(ctx->secrets.early, "derived",
			  ctx->transcript.empty, dgst);
	/* 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba */

	/* ECDHE extract == Handshake secret. Can be used as it is. */
	hkdf_sha256_extract(dgst, sizeof(dgst), ctx->secrets.shared, 32,
			    ctx->secrets.hand);

	/* Client/Server handshake traffic secrets. */
	/* The hash of the transcript. Use as it is. */
	tls_derive_secret(ctx->secrets.hand, "c hs traffic",
			  ctx->transcript.shello,
			  ctx->secrets.hand_traffic[TLS_CLIENT]);
	tls_derive_secret(ctx->secrets.hand, "s hs traffic",
			  ctx->transcript.shello,
			  ctx->secrets.hand_traffic[TLS_SERVER]);

	/* Client's write traffic key/iv. */
	p = ctx->secrets.hand_traffic[TLS_CLIENT];
	tls_hkdf_expand_label(p, "key", NULL,
			      ctx->secrets.hand_traffic_key[TLS_CLIENT], 32);
	tls_hkdf_expand_label(p, "iv", NULL,
			      ctx->secrets.hand_traffic_iv[TLS_CLIENT], 12);

	/* Server's write traffic key/iv. */
	p = ctx->secrets.hand_traffic[TLS_SERVER];
	tls_hkdf_expand_label(p, "key", NULL,
			      ctx->secrets.hand_traffic_key[TLS_SERVER], 32);
	tls_hkdf_expand_label(p, "iv", NULL,
			      ctx->secrets.hand_traffic_iv[TLS_SERVER], 12);
}

static void tls_derive_early_secrets(struct tls_ctx *ctx, const void *chello,
				     int len)
{
	int sz;
	struct sha256_ctx hctx;
	static uint8_t dgst[SHA256_DIGEST_LEN];

	sz = sizeof(struct tls_rec_hw);
	sha256_init(&hctx);
	sha256_update(&hctx, (const uint8_t *)chello + sz, len - sz);

	/* Save the context to process subsequent messages. */
	ctx->transcript.hctx = hctx;
	sha256_final(&hctx, ctx->transcript.chello);

	memset(dgst, 0, sizeof(dgst));

	/* Early Secret. We do not support PSK. */
	hkdf_sha256_extract(NULL, 0, dgst, sizeof(dgst), ctx->secrets.early);
	/* 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a */
}

static int tls_decipher_handshake(struct tls_ctx *ctx, void *rec, int len)
{
	int i, sz, other;
	uint64_t seq;
	uint8_t iv[12], *out;
	const uint8_t *p;

	other = TLS_SERVER;
	if (ctx->role == TLS_SERVER)
		other = TLS_CLIENT;

	memcpy(iv, ctx->secrets.hand_traffic_iv[other], sizeof(iv));

	seq = htole64(ctx->seq);
	p = (const uint8_t *)&seq;
	for (i = 0; i < 8; ++i)
		iv[11 - i] ^= p[i];

	sz = sizeof(struct tls_rec_hw);
	out = (uint8_t *)rec + sz;
	len -= sz;
	sz = aead_dec(ctx->secrets.hand_traffic_key[other], iv,
		      out, len, rec, sz, out);

	/* TLSInnerPlainText. Skip zeroes. */
	for (i = sz - 1; i >= 0; --i)
		if (out[i])
			break;

	/* Should be a handshake as expected. */
	assert(out[i] == TLS_RT_HAND);

	/* Length of the handshake message. */
	return i;
}

void tls_client_machine(struct tls_ctx *ctx, const char *ip, short port)
{
	FILE *f;
	enum tls_client_state cs;
	int n, sock, ret, sz;
	uint8_t *buf;
	struct sockaddr_in srvr = {0};
	struct tls_hand_hw *hhw;
	struct tls_rec_hw *rhw;
	struct tls_rec_sw *rsw;

	assert(ctx->role == TLS_CLIENT);

	goto skip;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	srvr.sin_family = AF_INET;
	srvr.sin_port = htons((short)port);
	inet_pton(AF_INET, ip, &srvr.sin_addr);
	ret = connect(sock, (const struct sockaddr *)&srvr, sizeof(srvr));
	assert(ret == 0);
skip:
	ctx->client_state = TLSC_START;
	buf = malloc(32*1024);

	for (;;) {
		rsw = NULL;

		switch (ctx->client_state) {
		case TLSC_WAIT_EE:
		case TLSC_WAIT_CERT_CR:
		case TLSC_WAIT_CERT:
		case TLSC_WAIT_CV:
		case TLSC_WAIT_FINISHED:
			/* rhw is not assigned. */
			//n = recv(sock, buf, sizeof(*rhw), 0);
			n = fread(buf, 1, sizeof(*rhw), f);
			assert(n == sizeof(*rhw));

			rhw = (struct tls_rec_hw *)buf;
			assert(rhw->type == TLS_RT_DATA);
			sz = ntohs(rhw->len);

			//n = recv(sock, rhw + 1, ntohs(rhw->len), 0);
			n = fread(rhw + 1, 1, sz, f);
			assert(n == sz);
			n += sizeof(*rhw);

			n = tls_decipher_handshake(ctx, buf, n);

			/* Craft a handshake record for deserialization. */
			rhw->type = TLS_RT_HAND;
			rhw->len = htons(n);
			n += sizeof(*rhw);
			rsw = tls_deserialize_rec(ctx, buf, n);

			cs = ctx->client_state;
			if (cs == TLSC_WAIT_EE)
				cs = TLSC_WAIT_CERT_CR;
			else if (cs == TLSC_WAIT_CERT_CR)
				cs = TLSC_WAIT_CV;	/* We recv CERT. */
			else if (cs == TLSC_WAIT_CERT)
				cs = TLSC_WAIT_CV;
			else if (cs == TLSC_WAIT_CV)
				cs = TLSC_WAIT_FINISHED;
			else if (cs == TLSC_WAIT_FINISHED)
				cs = TLSC_CONN;
			else
				assert(0);
			ctx->client_state = cs;
			++ctx->seq;
			break;
		case TLSC_WAIT_CCS:
			/* rhw is not assigned. */
			//n = recv(sock, buf, sizeof(*rhw), 0);
			n = fread(buf, 1, sizeof(*rhw), f);
			assert(n == sizeof(*rhw));

			rhw = (struct tls_rec_hw *)buf;
			assert(rhw->type == TLS_RT_CCS);
			sz = ntohs(rhw->len);
			assert(sz == 1);

			//n = recv(sock, rhw + 1, ntohs(rhw->len), 0);
			n = fread(rhw + 1, 1, sz, f);
			assert(n == sz);
			ctx->seq = 0;
			ctx->client_state = TLSC_WAIT_EE;
			break;
		case TLSC_WAIT_SH:
			/* rhw is not assigned. */
			//n = recv(sock, buf, sizeof(*rhw), 0);
			n = fread(buf, 1, sizeof(*rhw), f);
			assert(n == sizeof(*rhw));

			rhw = (struct tls_rec_hw *)buf;
			hhw = (struct tls_hand_hw *)(rhw + 1);

			assert(rhw->type == TLS_RT_HAND);
			sz = ntohs(rhw->len);

			//n = recv(sock, rhw + 1, ntohs(rhw->len), 0);
			n = fread(rhw + 1, 1, sz, f);
			assert(n == sz);
			assert(hhw->type == TLS_HT_SHELLO);
			n += sizeof(*rhw);

			/*
			 * Deserialize fills in the server's ECHDE key
			 * share.
			 */
			rsw = tls_deserialize_rec(ctx, buf, n);

			/* Calculate the CH,SH transcript hash. */

			tls_derive_handshake_secrets(ctx, buf, n);
			ctx->client_state = TLSC_WAIT_CCS;
			break;
		case TLSC_START:
			rsw = tls_new_chello(ctx);
			n = rsw->hw.len + sizeof(rsw->hw);
			assert( n > 0 && n < 32 * 1024);
			tls_serialize_rec(buf, n, rsw);

			tls_derive_early_secrets(ctx, buf, n);
			f = fopen("/tmp/shello", "rb");
#if 0
			ret = send(sock, buf, n, 0);
			assert(ret == n);
#endif
			ctx->client_state = TLSC_WAIT_SH;
			break;
		default:
			assert(0);
		}
		free(rsw);
	}
}
