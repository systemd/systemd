/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdint.h>

#include "sparse-endian.h"

static inline uint16_t unaligned_read_be16(const be16_t *u) {
        return (((uint16_t) ((uint8_t*) u)[0]) << 8) |
                ((uint16_t) ((uint8_t*) u)[1]);
}

static inline uint32_t unaligned_read_be32(const be32_t *u) {
        return (((uint32_t) unaligned_read_be16((be16_t*) u)) << 16) |
                ((uint32_t) unaligned_read_be16((be16_t*) u + 1));
}

static inline uint64_t unaligned_read_be64(const be64_t *u) {
        return (((uint64_t) unaligned_read_be32((be32_t*) u)) << 32) |
                ((uint64_t) unaligned_read_be32((be32_t*) u + 1));
}

static inline void unaligned_write_be16(be16_t *u, uint16_t a) {
        ((uint8_t*) u)[0] = (uint8_t) (a >> 8);
        ((uint8_t*) u)[1] = (uint8_t) a;
}

static inline void unaligned_write_be32(be32_t *u, uint32_t a) {
        unaligned_write_be16((be16_t*) u, (uint16_t) (a >> 16));
        unaligned_write_be16((be16_t*) u + 1, (uint16_t) a);
}

static inline void unaligned_write_be64(be64_t *u, uint64_t a) {
        unaligned_write_be32((be32_t*) u, (uint32_t) (a >> 32));
        unaligned_write_be32((be32_t*) u + 1, (uint32_t) a);
}
