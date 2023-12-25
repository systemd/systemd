/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Network Network;

typedef struct Neighbor {
        Network *network;
        Link *link;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;

        unsigned n_ref;

        int family;
        union in_addr_union in_addr;
        struct hw_addr_data ll_addr;
} Neighbor;

Neighbor* neighbor_ref(Neighbor *neighbor);
Neighbor* neighbor_unref(Neighbor *neighbor);

int neighbor_get(Link *link, const Neighbor *in, Neighbor **ret);
int neighbor_remove(Neighbor *neighbor, Link *link);

int network_drop_invalid_neighbors(Network *network);

int link_drop_managed_neighbors(Link *link);
int link_drop_foreign_neighbors(Link *link);
void link_foreignize_neighbors(Link *link);

int link_request_static_neighbors(Link *link);

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(Neighbor, neighbor);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_address);
CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_lladdr);
