/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/in6.h>

#include "forward.h"

typedef struct sd_ndisc_neighbor {
        unsigned n_ref;

        ICMP6Packet *packet;

        uint32_t flags;
        struct in6_addr target_address;

        Set *options;
} sd_ndisc_neighbor;

sd_ndisc_neighbor* ndisc_neighbor_new(ICMP6Packet *packet);
int ndisc_neighbor_parse(sd_ndisc *nd, sd_ndisc_neighbor *na);
