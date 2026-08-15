/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct sd_ndisc_router_solicit {
        unsigned n_ref;

        ICMP6Packet *packet;

        Set *options;
} sd_ndisc_router_solicit;

sd_ndisc_router_solicit* ndisc_router_solicit_new(ICMP6Packet *packet);
int ndisc_router_solicit_parse(sd_radv *ra, sd_ndisc_router_solicit *rs);
