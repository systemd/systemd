/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
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
        uint64_t lifetime_usec;
        uint64_t retrans_time_usec;

        uint8_t hop_limit;
        uint32_t mtu;
        uint64_t icmp6_ratelimit_usec;
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
int ndisc_router_parse(sd_ndisc *nd, sd_ndisc_router *rt);
