/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "netem.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"

typedef struct QDiscs {
        NetworkConfigSection *section;
        Network *network;

        Link *link;

        int family;

        uint32_t handle;
        uint32_t parent;

        bool has_network_emulator:1;

        NetworkEmulator ne;
} QDiscs;

void qdisc_free(QDiscs *qdisc);
int qdisc_new_static(Network *network, const char *filename, unsigned section_line, QDiscs **ret);

int qdisc_configure(Link *link, QDiscs *qdisc);

DEFINE_NETWORK_SECTION_FUNCTIONS(QDiscs, qdisc_free);

CONFIG_PARSER_PROTOTYPE(config_parse_tc_qdiscs_parent);
