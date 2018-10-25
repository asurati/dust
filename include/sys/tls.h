/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_TLS_H_
#define _SYS_TLS_H_

#include <stdint.h>

#include <ec.h>
#include <sha2.h>

enum tls_rec_type {
	TLS_RT_HAND = 0x16,
	TLS_RT_CIPHER = 0x14,
	TLS_RT_DATA = 0x17,
};

enum tls_hand_type {
	TLS_HT_CHELLO = 1,
	TLS_HT_SHELLO = 2,
};

struct tls_hand_hw {
	uint8_t type;
	uint8_t lenhi;
	uint16_t lenlo;
} __attribute__((packed));

struct tls_rec_hw {
	uint8_t type;
	uint16_t ver;
	uint16_t len;
} __attribute__((packed));

struct tls_chello_hw {
	uint16_t ver;
	uint8_t rnd[32];
	uint8_t sess_len;
	uint16_t cipher_len;	/* Our client sends only 1 cipher. */
	uint16_t cipher;
	uint8_t comp_len;
	uint8_t comp;		/* Implies comp_len must be set to 1. */
	uint16_t exts_len;
} __attribute__((packed));

struct tls_shello_hw {
	uint16_t ver;
	uint8_t rnd[32];
	uint8_t sess_len;
	uint16_t cipher;
	uint8_t comp;
	uint16_t exts_len;
} __attribute__((packed));

struct tls_ext_hw {
	uint16_t type;
	uint16_t len;
} __attribute__((packed));

/* key share entry. */
struct tls_kse_hw {
	uint16_t group;
	uint16_t klen;
} __attribute__((packed));





/* Do not use any pointers in the sw structures. */
struct tls_ext_sw {
	struct tls_ext_hw hw;
	uint8_t data[0x10000];
};

struct tls_chello_sw {
	struct tls_chello_hw hw;
	struct tls_ext_sw exts[8];
};

struct tls_shello_sw {
	struct tls_shello_hw hw;
	struct tls_ext_sw exts[8];
};

struct tls_hand_sw {
	struct tls_hand_hw hw;
	union {
		struct tls_chello_sw chello;
		struct tls_shello_sw shello;
	} u;
};

struct tls_rec_sw {
	struct tls_rec_hw hw;
	union {
		struct tls_hand_sw hand;
		uint8_t data[0x1000];
	} u;
};

struct tls_ctx {
	uint8_t *priv, *pub[2], *shared;
	void *chello;
	void *shello;
	uint8_t es[SHA256_DIGEST_LEN];
	uint8_t hs[SHA256_DIGEST_LEN];
	uint8_t chts[SHA256_DIGEST_LEN];
	uint8_t shts[SHA256_DIGEST_LEN];
	uint8_t ms[SHA256_DIGEST_LEN];
	int chello_len;
	int shello_len;
	int klen;
	int state;
};
#endif
