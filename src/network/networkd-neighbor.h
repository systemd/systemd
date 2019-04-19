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

        LIST_FIELDS(Neighbor, neighbors);
};

void neighbor_free(Neighbor *neighbor);

DEFINE_NETWORK_SECTION_FUNCTIONS(Neighbor, neighbor_free);

int neighbor_configure(Neighbor *neighbor, Link *link, link_netlink_message_handler_t callback);
int neighbor_remove(Neighbor *neighbor, Link *link, link_netlink_message_handler_t callback);

int neighbor_get(Link *link, int family, const union in_addr_union *addr, const union lladdr_union *lladdr, size_t lladdr_size, Neighbor **ret);
int neighbor_add(Link *link, int family, const union in_addr_union *addr, const union lladdr_union *lladdr, size_t lladdr_size, Neighbor **ret);
int neighbor_add_foreign(Link *link, int family, const union in_addr_union *addr, const union lladdr_union *lladdr, size_t lladdr_size, Neighbor **ret);
bool neighbor_equal(const Neighbor *n1, const Neighbor *n2);

int neighbor_section_verify(Neighbor *neighbor);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_address);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_lladdr);
