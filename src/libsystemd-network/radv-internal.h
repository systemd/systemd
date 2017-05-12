#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2017 Intel Corporation. All rights reserved.

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

#include "sd-radv.h"

#include "log.h"
#include "list.h"
#include "sparse-endian.h"

struct sd_radv_prefix {
        unsigned n_ref;

        struct {
                uint8_t type;
                uint8_t length;
                uint8_t prefixlen;
                uint8_t flags;
                be32_t valid_lifetime;
                be32_t preferred_lifetime;
                uint32_t reserved;
                struct in6_addr in6_addr;
        } _packed_ opt;

        LIST_FIELDS(struct sd_radv_prefix, prefix);
};

#define log_radv_full(level, error, fmt, ...) log_internal(level, error, __FILE__, __LINE__, __func__, "RADV: " fmt, ##__VA_ARGS__)
#define log_radv_errno(error, fmt, ...) log_radv_full(LOG_DEBUG, error, fmt, ##__VA_ARGS__)
#define log_radv_warning_errno(error, fmt, ...) log_radv_full(LOG_WARNING, error, fmt, ##__VA_ARGS__)
#define log_radv(fmt, ...) log_radv_errno(0, fmt, ##__VA_ARGS__)
