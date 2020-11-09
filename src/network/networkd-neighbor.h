/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef Manager Manager;
typedef Network Network;
typedef Link Link;

union lladdr_union {
        struct ether_addr mac;
        union in_addr_union ip;
};

typedef struct Neighbor {
        Network *network;
        Link *link;
        NetworkConfigSection *section;

        int family;
        union in_addr_union in_addr;
        union lladdr_union lladdr;
        size_t lladdr_size;
} Neighbor;

Neighbor *neighbor_free(Neighbor *neighbor);

void network_drop_invalid_neighbors(Network *network);

int link_set_neighbors(Link *link);
int link_drop_neighbors(Link *link);
int link_drop_foreign_neighbors(Link *link);

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_address);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_lladdr);
