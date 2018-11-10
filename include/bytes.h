/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _BYTES_H_
#define _BYTES_H_

#include <stdint.h>

static __inline__ uint64_t bswap64(uint64_t x)
{
	return __builtin_bswap64(x);
}

static __inline__ uint16_t bswap16(uint16_t x)
{
	return __builtin_bswap16(x);
}

static __inline__ uint32_t bswap32(uint32_t x)
{
	return __builtin_bswap32(x);
}

static __inline__ uint64_t identity64(uint64_t x)
{
	return x;
}

static __inline__ uint16_t identity16(uint16_t x)
{
	return x;
}

static __inline__ uint32_t identity32(uint32_t x)
{
	return x;
}

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe16(x)			identity16(x)
#define htobe32(x)			identity32(x)
#define htobe64(x)			identity64(x)
#define be16toh(x)			identity16(x)
#define be32toh(x)			identity32(x)
#define be64toh(x)			identity64(x)

#define htole16(x)			bswap16(x)
#define htole32(x)			bswap32(x)
#define htole64(x)			bswap64(x)
#define le16toh(x)			bswap16(x)
#define le32toh(x)			bswap32(x)
#define le64toh(x)			bswap64(x)
#else
#define htobe16(x)			bswap16(x)
#define htobe32(x)			bswap32(x)
#define htobe64(x)			bswap64(x)
#define be16toh(x)			bswap16(x)
#define be32toh(x)			bswap32(x)
#define be64toh(x)			bswap64(x)

#define htole16(x)			identity16(x)
#define htole32(x)			identity32(x)
#define htole64(x)			identity64(x)
#define le16toh(x)			identity16(x)
#define le32toh(x)			identity32(x)
#define le64toh(x)			identity64(x)
#endif
#endif
