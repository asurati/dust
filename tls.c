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

#include <sys/tls.h>

const char *c25519_prime	=
"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed";
const char *c25519_a		= "76d06";	// hex(486662)
const char *c25519_b		= "1";
const char *c25519_gx		= "9";
const char *c25519_order	=
"1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed";

const char *priv_str	=
"59effe2eb776d8e7118dda26b46cce413bfa0e2d4993acabaae91cf16c8c7d28";
const char *pub_str	=
"671e3b404cd8512b5077822a2e7764d614cdda6f67d3c6433ce63d5bcb132b7d";

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
#endif

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

	/* TODO overflow */
	n = strlen(label);
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

#if 0
// https://github.com/project-everest/ci-logs/blob/master/everest-test-10b31d91-20801.all
static const uint8_t sh[32] = {
	0x67,0x32,0x85,0x96,0x5d,0xfa,0x28,0xcd,
	0x80,0x2f,0x14,0x83,0x87,0x0a,0x1c,0xf7,
	0x2b,0x92,0x61,0x7b,0xc1,0xda,0x14,0xec,
	0x16,0xe4,0xd3,0x9b,0x6b,0xfa,0x24,0x72,
};
#endif

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
	priv = bn_new_from_bytes(ctx->priv, ctx->klen);
	t = bn_new_from_bytes(ctx->pub[1], ctx->klen);
	pub = ec_point_new(ec, t, NULL, NULL);
	ec_scale(ec, pub, priv);
	bn_free(priv);
	bn_free(t);

	t = ec_point_x(ec, pub);
	ctx->shared = bn_to_bytes(t, &n);
	assert(n == ctx->klen);
	bn_free(t);
	ec_point_free(ec, pub);
	ec_free(ec);

	memset(dgst, 0, sizeof(dgst));

	/* Early Secret. */
	hkdf_sha256_extract(NULL, 0, dgst, sizeof(dgst), ctx->es);
	/* 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a */
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", ctx->es[i]);
	printf("\n");

	/*
	 * Salt for ECDHE extract. Transcript sent is empty. So thash is the
	 * hash of the empty string.
	 */
	sha256_init(&hctx);
	sha256_final(&hctx, dgst);
	tls_derive_secret(ctx->es, "derived", dgst, dgst);
	/* 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba */
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", dgst[i]);
	printf("\n");

	/* ECDHE extract == Handshake secret. */
	hkdf_sha256_extract(dgst, sizeof(dgst), ctx->shared, ctx->klen,
			    ctx->hs);
	for (i = 0; i < SHA256_DIGEST_LEN; ++i)
		printf("%02x", ctx->hs[i]);
	printf("\n");

	/* Client/Server handshake traffic secrets. */
	n = sizeof(struct tls_rec_hw);
	sha256_init(&hctx);
	sha256_update(&hctx, (char *)ctx->chello + n, ctx->chello_len - n);
	sha256_update(&hctx, (char *)ctx->shello + n, ctx->shello_len - n);
	sha256_final(&hctx, dgst);
	tls_derive_secret(ctx->hs, "c hs traffic", dgst, ctx->chts);
	tls_derive_secret(ctx->hs, "s hs traffic", dgst, ctx->shts);
	return;
	// https://tlswg.github.io/draft-ietf-tls-tls13-vectors/draft-ietf-tls-tls13-vectors.html#rfc.section.3
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

	priv = bn_new_from_string(priv_str, 16);
	ctx->priv = bn_to_bytes(priv, &n);
	assert(n == 32);

	ec = ec_new_montgomery(&emp);
	pub = ec_gen_public(ec, priv);
	t = ec_point_x(ec, pub);
	ctx->pub[0] = bn_to_bytes(t, &n);
	assert(n == 32);
	/*
	 * We need to change the endiannce of the public key and check
	 * the encryption.
	 */

	bn_free(t);
	ec_point_free(ec, pub);
	ec_free(ec);
	bn_free(priv);
	return ctx;
}

void tls_decipher_data(struct tls_ctx *ctx, uint8_t *buf, size_t len)
{
	int i;
	uint8_t key[32];
	uint8_t iv[8];
	struct chacha20_ctx dec;

	tls_hkdf_expand_label(ctx->shts, "key", NULL, key, 32);
	tls_hkdf_expand_label(ctx->shts, "iv", NULL, iv, 8);

	chacha20_init(&dec, key, 32, iv);
	chacha20_dec(&dec, buf, buf, len);
	for (i = 0; i < (int)len; ++i)
		printf("%02x ", buf[i]);
	printf("\n");
	assert(0);
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
parse:
	f = fopen("/tmp/shello", "rb");
	n = fread(buf, 1, 4096, f);
	fclose(f);

	len = n;
	for (;len;) {
		sw = tls_deserialize_rec(buf, len);
		n = sw->hw.len + sizeof(sw->hw);
		if (sw->hw.type == TLS_RT_DATA) {
			tls_decipher_data(ctx, sw->u.data, sw->hw.len);
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
