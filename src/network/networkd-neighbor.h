/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "macro.h"

typedef struct Neighbor Neighbor;

#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"

union lladdr_union {
        struct ether_addr mac;
        union in_addr_union ip;
};

struct Neighbor {
        Network *network;
        Link *link;
        NetworkConfigSection *section;

        int family;
        union in_addr_union in_addr;
        union lladdr_union lladdr;
        size_t lladdr_size;
};

void neighbor_free(Neighbor *neighbor);
int neighbor_section_verify(Neighbor *neighbor);

int neighbor_remove(Neighbor *neighbor, Link *link);

int neighbor_add(Link *link, const Neighbor *in, Neighbor **ret);
bool neighbor_equal(const Neighbor *n1, const Neighbor *n2);

int link_set_neighbors(Link *link);

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_address);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_lladdr);
