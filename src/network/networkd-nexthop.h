/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc.
 */

#pragma once

#include "conf-parser.h"
#include "macro.h"

typedef struct NextHop NextHop;
typedef struct NetworkConfigSection NetworkConfigSection;

#include "networkd-network.h"
#include "networkd-util.h"

struct NextHop {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        unsigned char protocol;

        int family;
        uint32_t oif;
        uint32_t id;

        union in_addr_union gw;

        LIST_FIELDS(NextHop, nexthops);
};

void nexthop_free(NextHop *nexthop);

int link_set_nexthop(Link *link);

int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

int nexthop_section_verify(NextHop *nexthop);

CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_id);
CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_gateway);
