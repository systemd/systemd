/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc.
 */

#pragma once

#include <inttypes.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Network Network;

typedef struct NextHop {
        Network *network;
        NetworkConfigSection *section;

        Manager *manager;
        Link *link;

        uint8_t protocol;

        uint32_t id;
        bool blackhole;
        int family;
        union in_addr_union gw;
        int onlink;
} NextHop;

NextHop *nexthop_free(NextHop *nexthop);

void network_drop_invalid_nexthops(Network *network);

int link_set_nexthops(Link *link);
int link_drop_nexthops(Link *link);
int link_drop_foreign_nexthops(Link *link);

int manager_get_nexthop_by_id(Manager *manager, uint32_t id, NextHop **ret);
int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_id);
CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_gateway);
CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_family);
CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_onlink);
CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_blackhole);
