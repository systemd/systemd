/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "networkd-forward.h"
#include "networkd-util.h"

typedef struct Neighbor {
        Network *network;
        Link *link;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;

        unsigned n_ref;

        struct in_addr_data dst_addr;
        struct hw_addr_data ll_addr;
} Neighbor;

DECLARE_TRIVIAL_REF_UNREF_FUNC(Neighbor, neighbor);
DEFINE_SECTION_CLEANUP_FUNCTIONS(Neighbor, neighbor_unref);

typedef int (*neighbor_netlink_handler_t)(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                Neighbor *neighbor);

int neighbor_new(Neighbor **ret);

int neighbor_get(Link *link, const Neighbor *in, Neighbor **ret);
int neighbor_remove(Neighbor *neighbor, Link *link);

int network_drop_invalid_neighbors(Network *network);

int link_drop_static_neighbors(Link *link);
int link_drop_unmanaged_neighbors(Link *link);

int link_request_neighbor(
                Link *link,
                const Neighbor *neighbor,
                unsigned *message_counter,
                neighbor_netlink_handler_t netlink_handler);
int link_request_static_neighbors(Link *link);

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(Neighbor, neighbor);

typedef enum NeighborConfParserType {
        NEIGHBOR_DESTINATION_ADDRESS,
        NEIGHBOR_LINK_LAYER_ADDRESS,
        _NEIGHBOR_CONF_PARSER_MAX,
        _NEIGHBOR_CONF_PARSER_INVALID = -EINVAL,
} NeighborConfParserType;

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_section);
