/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "macro.h"

typedef struct MultiPathRoute MultiPathRoute;
typedef struct NetworkConfigSection NetworkConfigSection;

#include "networkd-network.h"
#include "networkd-util.h"

struct MultiPathRoute {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        int ifindex;
        int family;
        uint32_t weight;

        union in_addr_union gw;
};

int multipath_route_new(MultiPathRoute **ret);
void multipath_route_free(MultiPathRoute *route);
int multipath_section_verify(MultiPathRoute *route);

int multipath_route_configure(Link *link);

DEFINE_TRIVIAL_CLEANUP_FUNC(MultiPathRoute *, multipath_route_free);

CONFIG_PARSER_PROTOTYPE(config_parse_multipath_gateway);
CONFIG_PARSER_PROTOTYPE(config_parse_multipath_weight);
CONFIG_PARSER_PROTOTYPE(config_parse_multipath_link);
