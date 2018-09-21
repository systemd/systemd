/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2012 Josh Triplett <josh@joshtriplett.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#pragma once

#include <byteswap.h>
#include <endian.h>
#include <stdint.h>

#ifdef __CHECKER__
#define __sd_bitwise __attribute__((bitwise))
#define __sd_force __attribute__((force))
#else
#define __sd_bitwise
#define __sd_force
#endif

typedef uint16_t __sd_bitwise le16_t;
typedef uint16_t __sd_bitwise be16_t;
typedef uint32_t __sd_bitwise le32_t;
typedef uint32_t __sd_bitwise be32_t;
typedef uint64_t __sd_bitwise le64_t;
typedef uint64_t __sd_bitwise be64_t;

#undef htobe16
#undef htole16
#undef be16toh
#undef le16toh
#undef htobe32
#undef htole32
#undef be32toh
#undef le32toh
#undef htobe64
#undef htole64
#undef be64toh
#undef le64toh

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define bswap_16_on_le(x) __bswap_16(x)
#define bswap_32_on_le(x) __bswap_32(x)
#define bswap_64_on_le(x) __bswap_64(x)
#define bswap_16_on_be(x) (x)
#define bswap_32_on_be(x) (x)
#define bswap_64_on_be(x) (x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define bswap_16_on_le(x) (x)
#define bswap_32_on_le(x) (x)
#define bswap_64_on_le(x) (x)
#define bswap_16_on_be(x) __bswap_16(x)
#define bswap_32_on_be(x) __bswap_32(x)
#define bswap_64_on_be(x) __bswap_64(x)
#endif

static inline le16_t htole16(uint16_t value) { return (le16_t __sd_force) bswap_16_on_be(value); }
static inline le32_t htole32(uint32_t value) { return (le32_t __sd_force) bswap_32_on_be(value); }
static inline le64_t htole64(uint64_t value) { return (le64_t __sd_force) bswap_64_on_be(value); }

static inline be16_t htobe16(uint16_t value) { return (be16_t __sd_force) bswap_16_on_le(value); }
static inline be32_t htobe32(uint32_t value) { return (be32_t __sd_force) bswap_32_on_le(value); }
static inline be64_t htobe64(uint64_t value) { return (be64_t __sd_force) bswap_64_on_le(value); }

static inline uint16_t le16toh(le16_t value) { return bswap_16_on_be((uint16_t __sd_force)value); }
static inline uint32_t le32toh(le32_t value) { return bswap_32_on_be((uint32_t __sd_force)value); }
static inline uint64_t le64toh(le64_t value) { return bswap_64_on_be((uint64_t __sd_force)value); }

static inline uint16_t be16toh(be16_t value) { return bswap_16_on_le((uint16_t __sd_force)value); }
static inline uint32_t be32toh(be32_t value) { return bswap_32_on_le((uint32_t __sd_force)value); }
static inline uint64_t be64toh(be64_t value) { return bswap_64_on_le((uint64_t __sd_force)value); }

#undef __sd_bitwise
#undef __sd_force
