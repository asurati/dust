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
static const char *priv_str	=
"59effe2eb776d8e7118dda26b46cce413bfa0e2d4993acabaae91cf16c8c7d28";
/*
static const char *pub_str	=
"671e3b404cd8512b5077822a2e7764d614cdda6f67d3c6433ce63d5bcb132b7d";
*/

static void tls_hkdf_expand_label(uint8_t *out, int olen, const void *secret,
				  const char *label, const void *thash)
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
	hkdf_sha256_expand(out, olen, secret, SHA256_DIGEST_LEN, info, len);
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
static void tls_derive_secret(uint8_t *out, const void *secret,
			      const char *label, const void *thash)
{
	tls_hkdf_expand_label(out, SHA256_DIGEST_LEN, secret, label, thash);
}









#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static void tls_shello_pub(struct tls_ctx *ctx, const struct tls_ext_hw *exts,
			   int exts_len)
{
	int sz;
	const struct tls_ext_hw *ext;
	const struct tls_kse_hw *khw;

	for (ext = exts; exts_len;) {
		sz = ext->len + sizeof(*ext);
		exts_len -= sz;
		assert(exts_len >= 0);
		if (ext->type == 51) {
			khw = (struct tls_kse_hw *)(ext + 1);
			assert(khw->klen == 32);
			ctx->secrets.pub[1] = malloc(32);
			assert(ctx->secrets.pub[1]);
			memcpy(ctx->secrets.pub[1], khw + 1, 32);
			return;
		}
		ext = (struct tls_ext_hw *)((uint8_t *)ext + sz);
	}
	assert(0);
}

static void tls_convert_rec(struct tls_ctx *ctx, struct tls_rec_sw *rsw)
{
	(void)ctx;
	(void)rsw;
}
#else
static void tls_shello_pub(struct tls_ctx *ctx, const struct tls_ext_hw *exts,
			   int exts_len)
{
	(void)ctx;
	(void)exts;
	(void)exts_len;
}

static void tls_convert_ext(struct tls_ctx *ctx, void *buf, int len, int type)
{
	uint16_t *p;
	uint8_t *q;
	struct tls_kse_hw *khw;

	(void)len;

	switch (type) {
	case 13:
	case 10:
		/* Signature Algorithms List. */
		/* Supported Groups List. */
		p = (uint16_t *)buf;
		/* We support only 1. */
		p[0] = htons(p[0]);
		p[1] = htons(p[1]);
		break;
	case 43:
		/* Supported Versions List. */
		assert(ctx->role == TLS_CLIENT);
		if (ctx->client_state == TLSC_START)  {
			/* When chello, this type is a list. */
			q = (uint8_t *)buf;
			p = (uint16_t *)(q + 1);
			/* We support only 1. */
			p[0] = htons(p[0]);
		} else if (ctx->client_state == TLSC_WAIT_SH) {
			/* When shello, this type is singular. */
			p = (uint16_t *)buf;
			p[0] = htons(p[0]);
		} else {
			assert(0);
		}
		break;
	case 51:
		/* Key Share List. We support only 1. */
		assert(ctx->role == TLS_CLIENT);
		if (ctx->client_state == TLSC_START) {
			p = (uint16_t *)buf;
			khw = (struct tls_kse_hw *)(p + 1);
			p[0] = htons(p[0]);
			khw->group = htons(khw->group);
			khw->klen = htons(khw->klen);
		} else if (ctx->client_state == TLSC_WAIT_SH) {
			khw = (struct tls_kse_hw *)buf;
			khw->group = htons(khw->group);
			khw->klen = htons(khw->klen);
			assert(khw->klen == 32);
			ctx->secrets.pub[1] = malloc(32);
			assert(ctx->secrets.pub[1]);
			memcpy(ctx->secrets.pub[1], khw + 1, 32);
		}
		break;
	default:
		printf("%s: unsup %x\n", __func__, type);
		assert(0);
	}
}

/* Called when the rec is in network byte order form. */
static void tls_convert_exts(struct tls_ctx *ctx, struct tls_ext_hw *exts,
			     int exts_len)
{
	int len, sz, out;
	struct tls_ext_hw *ext, *t;

	assert(ctx->role == TLS_CLIENT);
	out = ctx->client_state == TLSC_START;

	if (out) {
		len = htons(exts_len);
		for (ext = exts; len; ext = t) {
			sz = ext->len + sizeof(*ext);
			t = (struct tls_ext_hw *)((uint8_t *)ext + sz);
			len -= sz;
			assert(len >= 0);
			tls_convert_ext(ctx, ext + 1, ext->len, ext->type);

			ext->len = htons(ext->len);
			ext->type = htons(ext->type);
		}
	} else {
		len = exts_len;
		for (ext = exts; len; ext = t) {
			ext->len = htons(ext->len);
			ext->type = htons(ext->type);
			sz = ext->len + sizeof(*ext);
			t = (struct tls_ext_hw *)((uint8_t *)ext + sz);
			len -= sz;
			assert(len >= 0);
			tls_convert_ext(ctx, ext + 1, ext->len, ext->type);
		}
	}
}

static void tls_convert_rec(struct tls_ctx *ctx, struct tls_rec_sw *rsw)
{
	struct tls_rec_hw *r;
	struct tls_hand_hw *h;
	struct tls_chello_hw *ch;
	struct tls_shello_hw *sh;
	struct tls_encext_hw *ee;

	r = rsw->rec;

	h = rsw->u1.hand;
	ch = rsw->u2.chello;
	sh = rsw->u2.shello;
	ee = rsw->u2.encext;

	r->ver = htons(r->ver);
	r->len = htons(r->len);
	if (r->type == TLS_RT_HAND) {
		h->lenlo = htons(h->lenlo);
		switch (h->type) {
		case TLS_HT_CHELLO:
			ch->ver = htons(ch->ver);
			ch->cipher_len = htons(ch->cipher_len);
			ch->cipher = htons(ch->cipher);
			ch->exts_len = htons(ch->exts_len);
			tls_convert_exts(ctx, rsw->exts, ch->exts_len);
			break;
		case TLS_HT_SHELLO:
			sh->ver = htons(sh->ver);
			sh->cipher = htons(sh->cipher);
			sh->exts_len = htons(sh->exts_len);
			tls_convert_exts(ctx, rsw->exts, sh->exts_len);
			break;
		case TLS_HT_ENCEXT:
			ee->exts_len = htons(ee->exts_len);
			assert(ee->exts_len == 0);
			break;
		case TLS_HT_CERT:
			printf("unsup CERT\n");
			break;
		case TLS_HT_CV:
			printf("unsup CV\n");
			break;
		case TLS_HT_FIN:
			printf("unsup FIN\n");
			break;
		default:
			printf("%d\n", h->type);
			assert(0);
		}
	} else {
		assert(0);
	}
	return;
}
#endif

static struct tls_rec_sw *tls_new_chello(const struct tls_ctx *ctx)
{
	int n;
	uint8_t *q;
	uint16_t *p;
	uint8_t *buf;
	struct tls_rec_sw *rsw;
	struct tls_rec_hw *r;
	struct tls_hand_hw *h;
	struct tls_chello_hw *ch;
	struct tls_ext_hw *ext;
	struct tls_kse_hw *khw;

	/* TODO Change the size once larger CHello is needed. */
	buf = malloc(512);
	assert(buf);

	rsw = malloc(sizeof(*rsw));
	assert(rsw);

	r = (struct tls_rec_hw *)buf;
	rsw->rec = r;
	r->type = TLS_RT_HAND;
	r->ver = TLS_12;

	h = (struct tls_hand_hw *)((uint8_t *)r + sizeof(*r));
	rsw->u1.hand = h;
	h->type = TLS_HT_CHELLO;

	ch = (struct tls_chello_hw *)((uint8_t *)h + sizeof(*h));
	rsw->u2.chello = ch;
	memset(ch->rnd, 0, 32);
	//rndm_fill(h->rnd, 32 << 3);
	ch->ver = TLS_12;
	ch->sess_len = 0;
	ch->cipher_len = 2;
	ch->cipher = 0x1303;	/* TLS_CHACHA20_POLY1305_SHA256. */
	ch->comp_len = 1;
	ch->comp = 0;		/* Compression = None. */
	ch->exts_len = 0;

	/* Supported Groups List. */
	ext = (struct tls_ext_hw *)((uint8_t *)ch + sizeof(*ch));
	rsw->exts = ext;
	p = (uint16_t *)(ext + 1);
	ext->type = 10;
	ext->len = 4;
	p[0] = 2;
	p[1] = 29;	/* X25519 */
	p += 2;
	ch->exts_len += ext->len;

	/* Signature Algorithms List. */
	ext = (struct tls_ext_hw *)p;
	p = (uint16_t *)(ext + 1);
	ext->type = 13;
	ext->len = 4;
	p[0] = 2;
	p[1] = 0x807;	/* Ed25519 */
	p += 2;
	ch->exts_len += ext->len;

	/* Supported Versions List. */
	ext = (struct tls_ext_hw *)p;
	q = (uint8_t *)(ext + 1);
	p = (uint16_t *)(q + 1);
	ext->type = 43;
	ext->len = 3;
	q[0] = 2;
	p[0] = 0x304;	/* TLSv1.3 */
	++p;
	ch->exts_len += ext->len;

	/* Key Share List. */
	ext = (struct tls_ext_hw *)p;
	p = (uint16_t *)(ext + 1);
	ext->type = 51;
	ext->len = sizeof(*khw) + 32 + 2;
	/* Client key share length. */
	p[0] = sizeof(*khw) + 32;
	khw = (struct tls_kse_hw *)(p + 1);
	khw->group = 29;	/* X25519. */
	khw->klen = 32;
	memcpy(khw + 1, ctx->secrets.pub[0], 32);
	ch->exts_len += ext->len;

	/* Fill in various lengths from bottom up. */
	ch->exts_len += 4 * sizeof(*ext);
	n = ch->exts_len + sizeof(*ch);
	h->lenhi = n >> 16;
	h->lenlo = n & 0xffff;
	r->len = n + sizeof(*h);
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

	emp.prime	= c25519_prime_be;
	emp.a		= c25519_a_be;
	emp.b		= c25519_b_be;
	emp.gx		= c25519_gx_be;
	emp.order	= c25519_order_be;

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

	/* Generate public key. */
	pub = EC_POINT_INVALID;
	ec_scale(ec, &pub, priv);
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

static void tls_derive_next_secret(uint8_t *out, const uint8_t *empty,
				   const uint8_t *prev, const uint8_t *ikm)
{
	static uint8_t salt[SHA256_DIGEST_LEN];
	static uint8_t zeroes[SHA256_DIGEST_LEN];

	/*
	 * Salt for the next extract. Transcript sent is empty. So thash is the
	 * hash of the empty string. The result can be used as it is.
	 */
	tls_derive_secret(salt, prev, "derived", empty);

	/* Next Secret. Can be used as it is. */
	if (ikm == NULL) {
		memset(zeroes, 0, sizeof(zeroes));
		hkdf_sha256_extract(out, salt, sizeof(salt), zeroes, 32);
	} else {
		hkdf_sha256_extract(out, salt, sizeof(salt), ikm, 32);
	}
}

static void tls_derive_traffic_ikm(uint8_t *t, uint8_t *tkey, uint8_t *tiv,
			      const uint8_t *secret, const char *label,
			      const uint8_t *thash)
{
	tls_derive_secret(t, secret, label, thash);
	tls_hkdf_expand_label(tkey, 32, t, "key", NULL);
	tls_hkdf_expand_label(tiv, 12, t, "iv", NULL);
}

static void tls_derive_master_secrets(struct tls_ctx *ctx)
{
	static struct sha256_ctx hctx;

	hctx = ctx->transcript.hctx;
	sha256_final(&hctx, ctx->transcript.sfin);

	tls_derive_next_secret(ctx->secrets.master, ctx->transcript.empty,
			       ctx->secrets.hand, NULL);
	tls_derive_traffic_ikm(ctx->secrets.app_traffic[TLS_CLIENT],
			       ctx->secrets.app_traffic_key[TLS_CLIENT],
			       ctx->secrets.app_traffic_iv[TLS_CLIENT],
			       ctx->secrets.master, "c ap traffic",
			       ctx->transcript.sfin);
	tls_derive_traffic_ikm(ctx->secrets.app_traffic[TLS_SERVER],
			       ctx->secrets.app_traffic_key[TLS_SERVER],
			       ctx->secrets.app_traffic_iv[TLS_SERVER],
			       ctx->secrets.master, "s ap traffic",
			       ctx->transcript.sfin);
}

static void tls_derive_handshake_secrets(struct tls_ctx *ctx)
{
	int sz;
	static struct sha256_ctx hctx;
	struct ec *ec;
	struct ec_point *pub;
	struct bn *t, *priv;
	struct ec_mont_params emp;

	/* Calculate the ECDHE shared secret. */
	emp.prime	= c25519_prime_be;
	emp.a		= c25519_a_be;
	emp.b		= c25519_b_be;
	emp.gx		= c25519_gx_be;
	emp.order	= c25519_order_be;

	ec = ec_new_montgomery(&emp);
	priv = bn_new_from_bytes_le(ctx->secrets.priv, 32);

	/*
	 * Server's x25519 key share arrives in the little-endian byte-array
	 * form on the network.
	 */
	t = bn_new_from_bytes_le(ctx->secrets.pub[1], 32);
	pub = ec_point_new(ec, t, NULL, NULL);
	ec_scale(ec, &pub, priv);
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

	hctx = ctx->transcript.hctx;
	sha256_final(&hctx, ctx->transcript.shello);

	tls_derive_next_secret(ctx->secrets.hand, ctx->transcript.empty,
			       ctx->secrets.early, ctx->secrets.shared);
	tls_derive_traffic_ikm(ctx->secrets.hand_traffic[TLS_CLIENT],
			       ctx->secrets.hand_traffic_key[TLS_CLIENT],
			       ctx->secrets.hand_traffic_iv[TLS_CLIENT],
			       ctx->secrets.hand, "c hs traffic",
			       ctx->transcript.shello);
	tls_derive_traffic_ikm(ctx->secrets.hand_traffic[TLS_SERVER],
			       ctx->secrets.hand_traffic_key[TLS_SERVER],
			       ctx->secrets.hand_traffic_iv[TLS_SERVER],
			       ctx->secrets.hand, "s hs traffic",
			       ctx->transcript.shello);
}

static void tls_derive_early_secrets(struct tls_ctx *ctx)
{
	static struct sha256_ctx hctx;
	static uint8_t zeroes[SHA256_DIGEST_LEN];

	hctx = ctx->transcript.hctx;
	sha256_final(&hctx, ctx->transcript.chello);

	memset(zeroes, 0, sizeof(zeroes));

	/* Early Secret. We do not support PSK. */
	hkdf_sha256_extract(ctx->secrets.early, NULL, 0, zeroes,
			    sizeof(zeroes));
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
	int n, sock, ret, sz, rhsz;
	uint8_t *buf;
	struct sockaddr_in srvr = {0};
	struct tls_rec_hw *r;
	struct tls_hand_hw *h;
	struct tls_shello_hw *sh;
	struct tls_rec_sw *rsw;

	(void)cs;
	assert(ctx->role == TLS_CLIENT);
	buf = malloc(32*1024);
	assert(buf);

	rhsz = sizeof(struct tls_rec_hw);

	goto skip;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	srvr.sin_family = AF_INET;
	srvr.sin_port = htons((short)port);
	inet_pton(AF_INET, ip, &srvr.sin_addr);
	ret = connect(sock, (const struct sockaddr *)&srvr, sizeof(srvr));
	assert(ret == 0);
	goto skip;
skip:
	/* TLSC_START */
	rsw = tls_new_chello(ctx);
	n = rsw->rec->len;

	ctx->client_state = TLSC_START;
	tls_convert_rec(ctx, rsw);

	/* Begin the trasncript hash. */
	sha256_init(&ctx->transcript.hctx);
	sha256_update(&ctx->transcript.hctx, (uint8_t *)rsw->rec + rhsz, n);
	tls_derive_early_secrets(ctx);

	f = fopen("/tmp/shello", "rb");
	//ret = send(sock, rsw->rec, n + rhsz, 0);
	//assert(ret == n);

	free(rsw->rec);
	ctx->client_state = TLSC_WAIT_SH;
	/* TLSC_START Ends */



	r = rsw->rec = (struct tls_rec_hw *)buf;
	for (;;) {
		/* Read a record header. */
		//n = recv(sock, buf, sizeof(*rhw), 0);
		n = fread(buf, 1, rhsz, f);
		assert(n == rhsz);

		/* Apply checks on the record header. Assign pointers. */
		switch (ctx->client_state) {
		case TLSC_WAIT_EE:
		case TLSC_WAIT_CERT:
		case TLSC_WAIT_CV:
		case TLSC_WAIT_FIN:
			assert(r->type == TLS_RT_DATA);
			h = rsw->u1.hand = (struct tls_hand_hw *)(r + 1);
			break;
		case TLSC_WAIT_CCS:
			assert(r->type == TLS_RT_CCS);
			assert(ntohs(r->len) == 1);
			break;
		case TLSC_WAIT_SH:
			assert(r->type == TLS_RT_HAND);
			h = rsw->u1.hand = (struct tls_hand_hw *)(r + 1);
			sh = rsw->u2.shello = (struct tls_shello_hw *)(h + 1);
			rsw->exts = (struct tls_ext_hw *)(sh + 1);
			break;
		default:
			assert(0);
			break;
		}

		/* Read the record payload. */
		sz = ntohs(r->len);
		//n = recv(sock, rhw + 1, ntohs(rhw->len), 0);
		n = fread(r + 1, 1, sz, f);
		assert(n == sz);

		/* Update the running transcript hash. */
		sha256_update(&ctx->transcript.hctx, r + 1, sz);

		/* Total size of the record. */
		n += rhsz;

		/* Process the record. */
		switch (ctx->client_state) {
		case TLSC_WAIT_EE:
		case TLSC_WAIT_CERT:
		case TLSC_WAIT_CV:
		case TLSC_WAIT_FIN:
			n = tls_decipher_handshake(ctx, buf, n);
			/* Craft a handshake record for deserialization. */
			r->type = TLS_RT_HAND;
			r->len = htons(n);

			tls_convert_rec(ctx, rsw);
			n += rhsz;

			cs = ctx->client_state;

			/*
			 * Calculate the signature over the transcript-hash
			 * and compare it with the signature received next
			 * in the CV state.
			 */
			if (cs == TLSC_WAIT_CERT) {
			}

			/* Calculate the MAC. */
			if (cs == TLSC_WAIT_CV) {
			}

			if (cs == TLSC_WAIT_FIN)
				tls_derive_master_secrets(ctx);

			if (cs == TLSC_WAIT_EE)
				cs = TLSC_WAIT_CERT;
			else if (cs == TLSC_WAIT_CERT)
				cs = TLSC_WAIT_CV;
			else if (cs == TLSC_WAIT_CV)
				cs = TLSC_WAIT_FIN;
			else if (cs == TLSC_WAIT_FIN)
				cs = TLSC_CONN;
			else
				assert(0);
			ctx->client_state = cs;
			++ctx->seq;
			break;
		case TLSC_WAIT_CCS:
			ctx->seq = 0;
			ctx->client_state = TLSC_WAIT_EE;
			break;
		case TLSC_WAIT_SH:
			assert(h->type == TLS_HT_SHELLO);
			tls_convert_rec(ctx, rsw);
			tls_shello_pub(ctx, rsw->exts, sh->exts_len);
			tls_derive_handshake_secrets(ctx);
			ctx->client_state = TLSC_WAIT_CCS;
			break;
		default:
			assert(0);
		}
	}
}
