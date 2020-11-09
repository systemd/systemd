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

        Link *link;

        unsigned char protocol;

        uint32_t id;
        int family;
        union in_addr_union gw;
} NextHop;

NextHop *nexthop_free(NextHop *nexthop);

void network_drop_invalid_nexthops(Network *network);

int link_set_nexthop(Link *link);

int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_id);
CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_gateway);
