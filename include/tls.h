/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _TLS_H_
#define _TLS_H_

struct tls_ctx;

struct tls_ctx
	*tls_ctx_new();
int	 tls_connect(struct tls_ctx *ctx, const char *ip, short port);
#endif
