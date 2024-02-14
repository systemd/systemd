/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-ndisc.h"

#include "time-util.h"

struct sd_ndisc_neighbor {
        unsigned n_ref;

        triple_timestamp timestamp;
        struct in6_addr address;

        /* The raw packet size. The data is appended to the object, accessible via NDIS_NEIGHBOR_RAW() */
        size_t raw_size;

        uint32_t flags;
        struct in6_addr target_address;
};

static inline void* NDISC_NEIGHBOR_RAW(const sd_ndisc_neighbor *rt) {
        return (uint8_t*) rt + ALIGN(sizeof(sd_ndisc_neighbor));
}

sd_ndisc_neighbor *ndisc_neighbor_new(size_t raw_size);
int ndisc_neighbor_parse(sd_ndisc *nd, sd_ndisc_neighbor *rt);
