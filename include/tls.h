/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _TLS_H_
#define _TLS_H_

struct tls_cli_ctx;

struct tls_cli_ctx
	*tls_cli_new(const uint8_t *pubkey, int klen);
int	 tls_cli_connect(struct tls_cli_ctx *ctx, const char *ip, short port);
#endif
