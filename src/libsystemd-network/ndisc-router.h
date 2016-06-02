#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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

#include "sd-ndisc.h"

#include "time-util.h"

struct sd_ndisc_router {
        unsigned n_ref;

        triple_timestamp timestamp;
        struct in6_addr address;

        /* The raw packet size. The data is appended to the object, accessible via NDIS_ROUTER_RAW() */
        size_t raw_size;

        /* The current read index for the iterative option interface */
        size_t rindex;

        uint64_t flags;
        unsigned preference;
        uint16_t lifetime;

        uint8_t hop_limit;
        uint32_t mtu;
};

static inline void* NDISC_ROUTER_RAW(const sd_ndisc_router *rt) {
        return (uint8_t*) rt + ALIGN(sizeof(sd_ndisc_router));
}

static inline void *NDISC_ROUTER_OPTION_DATA(const sd_ndisc_router *rt) {
        return ((uint8_t*) NDISC_ROUTER_RAW(rt)) + rt->rindex;
}

static inline uint8_t NDISC_ROUTER_OPTION_TYPE(const sd_ndisc_router *rt) {
        return ((uint8_t*) NDISC_ROUTER_OPTION_DATA(rt))[0];
}
static inline size_t NDISC_ROUTER_OPTION_LENGTH(const sd_ndisc_router *rt) {
        return ((uint8_t*) NDISC_ROUTER_OPTION_DATA(rt))[1] * 8;
}

sd_ndisc_router *ndisc_router_new(size_t raw_size);
int ndisc_router_parse(sd_ndisc_router *rt);
