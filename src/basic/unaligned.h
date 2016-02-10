#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <endian.h>
#include <stdint.h>

/* BE */

static inline uint16_t unaligned_read_be16(const void *_u) {
        const uint8_t *u = _u;

        return (((uint16_t) u[0]) << 8) |
                ((uint16_t) u[1]);
}

static inline uint32_t unaligned_read_be32(const void *_u) {
        const uint8_t *u = _u;

        return (((uint32_t) unaligned_read_be16(u)) << 16) |
                ((uint32_t) unaligned_read_be16(u + 2));
}

static inline uint64_t unaligned_read_be64(const void *_u) {
        const uint8_t *u = _u;

        return (((uint64_t) unaligned_read_be32(u)) << 32) |
                ((uint64_t) unaligned_read_be32(u + 4));
}

static inline void unaligned_write_be16(void *_u, uint16_t a) {
        uint8_t *u = _u;

        u[0] = (uint8_t) (a >> 8);
        u[1] = (uint8_t) a;
}

static inline void unaligned_write_be32(void *_u, uint32_t a) {
        uint8_t *u = _u;

        unaligned_write_be16(u, (uint16_t) (a >> 16));
        unaligned_write_be16(u + 2, (uint16_t) a);
}

static inline void unaligned_write_be64(void *_u, uint64_t a) {
        uint8_t *u = _u;

        unaligned_write_be32(u, (uint32_t) (a >> 32));
        unaligned_write_be32(u + 4, (uint32_t) a);
}

/* LE */

static inline uint16_t unaligned_read_le16(const void *_u) {
        const uint8_t *u = _u;

        return (((uint16_t) u[1]) << 8) |
                ((uint16_t) u[0]);
}

static inline uint32_t unaligned_read_le32(const void *_u) {
        const uint8_t *u = _u;

        return (((uint32_t) unaligned_read_le16(u + 2)) << 16) |
                ((uint32_t) unaligned_read_le16(u));
}

static inline uint64_t unaligned_read_le64(const void *_u) {
        const uint8_t *u = _u;

        return (((uint64_t) unaligned_read_le32(u + 4)) << 32) |
                ((uint64_t) unaligned_read_le32(u));
}

static inline void unaligned_write_le16(void *_u, uint16_t a) {
        uint8_t *u = _u;

        u[0] = (uint8_t) a;
        u[1] = (uint8_t) (a >> 8);
}

static inline void unaligned_write_le32(void *_u, uint32_t a) {
        uint8_t *u = _u;

        unaligned_write_le16(u, (uint16_t) a);
        unaligned_write_le16(u + 2, (uint16_t) (a >> 16));
}

static inline void unaligned_write_le64(void *_u, uint64_t a) {
        uint8_t *u = _u;

        unaligned_write_le32(u, (uint32_t) a);
        unaligned_write_le32(u + 4, (uint32_t) (a >> 32));
}
