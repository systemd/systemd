/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <endian.h>
#include <stdint.h>

/* BE */

static inline uint16_t unaligned_read_be16(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        return be16toh(u->x);
}

static inline uint32_t unaligned_read_be32(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        return be32toh(u->x);
}

static inline uint64_t unaligned_read_be64(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        return be64toh(u->x);
}

static inline void unaligned_write_be16(void *_u, uint16_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        u->x = be16toh(a);
}

static inline void unaligned_write_be32(void *_u, uint32_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        u->x = be32toh(a);
}

static inline void unaligned_write_be64(void *_u, uint64_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        u->x = be64toh(a);
}

/* LE */

static inline uint16_t unaligned_read_le16(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        return le16toh(u->x);
}

static inline uint32_t unaligned_read_le32(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        return le32toh(u->x);
}

static inline uint64_t unaligned_read_le64(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        return le64toh(u->x);
}

static inline void unaligned_write_le16(void *_u, uint16_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        u->x = le16toh(a);
}

static inline void unaligned_write_le32(void *_u, uint32_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        u->x = le32toh(a);
}

static inline void unaligned_write_le64(void *_u, uint64_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        u->x = le64toh(a);
}

#if __BYTE_ORDER == __BIG_ENDIAN
#define unaligned_read_ne16 unaligned_read_be16
#define unaligned_read_ne32 unaligned_read_be32
#define unaligned_read_ne64 unaligned_read_be64

#define unaligned_write_ne16 unaligned_write_be16
#define unaligned_write_ne32 unaligned_write_be32
#define unaligned_write_ne64 unaligned_write_be64
#else
#define unaligned_read_ne16 unaligned_read_le16
#define unaligned_read_ne32 unaligned_read_le32
#define unaligned_read_ne64 unaligned_read_le64

#define unaligned_write_ne16 unaligned_write_le16
#define unaligned_write_ne32 unaligned_write_le32
#define unaligned_write_ne64 unaligned_write_le64
#endif
