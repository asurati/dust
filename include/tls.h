/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _TLS_H_
#define _TLS_H_

int	tls_fill_chello(uint8_t *buf, int len, const uint8_t *pubkey);
int	tls_parse_records(const uint8_t *buf, int len, uint8_t *peerpub);
#endif
