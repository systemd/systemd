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

typedef enum {
        NEIGHBOR_LLADDR_MAC,
        NEIGHBOR_LLADDR_IP,
        _NEIGHBOR_LLADDR_MAX,
        _NEIGHBOR_LLADDR_INVALID = -1,
} NeighborLLAddressType;

struct Neighbor {
        Network *network;
        Link *link;
        NetworkConfigSection *section;

        int family;
        union in_addr_union in_addr;
        union {
                struct ether_addr mac;
                union in_addr_union ip;
        } lladdr;
        NeighborLLAddressType lladdr_type;

        LIST_FIELDS(Neighbor, neighbors);
};

void neighbor_free(Neighbor *neighbor);

DEFINE_NETWORK_SECTION_FUNCTIONS(Neighbor, neighbor_free);

int neighbor_configure(Neighbor *neighbor, Link *link, link_netlink_message_handler_t callback);

int neighbor_section_verify(Neighbor *neighbor);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_address);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_lladdr);
