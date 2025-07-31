/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/in6.h>

#include "forward.h"

typedef struct sd_ndisc_redirect {
        unsigned n_ref;

        ICMP6Packet *packet;

        struct in6_addr target_address;
        struct in6_addr destination_address;

        Set *options;
} sd_ndisc_redirect;

sd_ndisc_redirect* ndisc_redirect_new(ICMP6Packet *packet);
int ndisc_redirect_parse(sd_ndisc *nd, sd_ndisc_redirect *rd);
