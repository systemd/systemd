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

struct Neighbor {
        Network *network;
        Link *link;
        NetworkConfigSection *section;

        int family;
        union in_addr_union in_addr;
        bool mac_configured;
        struct ether_addr mac;

        LIST_FIELDS(Neighbor, neighbors);
};

void neighbor_free(Neighbor *neighbor);

DEFINE_TRIVIAL_CLEANUP_FUNC(Neighbor*, neighbor_free);

int neighbor_configure(Neighbor *neighbor, Link *link, link_netlink_message_handler_t callback);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_address);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_hwaddr);
