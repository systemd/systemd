/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <inttypes.h>
#include <linux/neighbour.h>

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "in-addr-util.h"

typedef struct Link Link;
typedef struct Network Network;

typedef enum NeighborCacheEntryFlags {
        NEIGHBOR_CACHE_ENTRY_FLAGS_USE = NTF_USE,
        NEIGHBOR_CACHE_ENTRY_FLAGS_SELF = NTF_SELF,
        NEIGHBOR_CACHE_ENTRY_FLAGS_MASTER = NTF_MASTER,
        NEIGHBOR_CACHE_ENTRY_FLAGS_ROUTER = NTF_ROUTER,
        _NEIGHBOR_CACHE_ENTRY_FLAGS_MAX,
        _NEIGHBOR_CACHE_ENTRY_FLAGS_INVALID = -EINVAL,
} NeighborCacheEntryFlags;

typedef struct BridgeFDB {
        Network *network;
        ConfigSection *section;

        uint32_t vni;

        int family;
        uint16_t vlan_id;

        struct ether_addr mac_addr;
        union in_addr_union destination_addr;
        NeighborCacheEntryFlags ntf_flags;
        char *outgoing_ifname;
        int outgoing_ifindex;
} BridgeFDB;

BridgeFDB *bridge_fdb_free(BridgeFDB *fdb);

void network_drop_invalid_bridge_fdb_entries(Network *network);

int link_request_static_bridge_fdb(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_fdb_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_vlan_id);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_destination);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_vxlan_vni);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_ntf_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_interface);
