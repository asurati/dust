/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_TLS_H_
#define _SYS_TLS_H_

#include <stdint.h>

struct tls_ext_supported_groups {
	uint16_t len;
	uint16_t groups[];
} __attribute__((packed));

struct tls_ext_sign_algos {
	uint16_t len;
	uint16_t algos[];
} __attribute__((packed));

struct tls_ext_supported_vers {
	uint8_t len;
	uint16_t vers[];
} __attribute__((packed));

struct tls_ext_key_share_entry {
	uint16_t group;
	uint16_t klen;
	uint8_t key[];
} __attribute__((packed));

struct tls_ext_key_share {
	uint16_t len;
	uint8_t data[];
} __attribute__((packed));

struct tls_ext {
	uint16_t type;
	uint16_t len;
	uint8_t data[];
} __attribute__((packed));

struct tls_exts {
	uint16_t len;
	uint8_t data[];
} __attribute__((packed));

struct tls_comp {
	uint8_t len;
	uint8_t comp[];
} __attribute__((packed));

struct tls_ciphers {
	uint16_t len;
	uint16_t ciphers[];
} __attribute__((packed));

struct tls_sess_id {
	uint8_t len;
	uint8_t id[];
} __attribute__((packed));

struct tls_chello {
	uint16_t ver;
	uint8_t rnd[32];
	uint8_t data[];
} __attribute__((packed));

struct tls_hand {
	uint8_t type;
	uint8_t lenhi;
	uint16_t lenlo;
	uint8_t data[];
} __attribute__((packed));

struct tls_rec {
	uint8_t type;
	uint16_t ver;
	uint16_t len;
	uint8_t data[];
} __attribute__((packed));
#endif
