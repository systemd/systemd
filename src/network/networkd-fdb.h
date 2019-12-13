/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <linux/neighbour.h>

#include "conf-parser.h"
#include "list.h"
#include "macro.h"
#include "networkd-util.h"

typedef struct Network Network;
typedef struct FdbEntry FdbEntry;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

typedef enum NeighborCacheEntryFlags {
        NEIGHBOR_CACHE_ENTRY_FLAGS_USE = NTF_USE,
        NEIGHBOR_CACHE_ENTRY_FLAGS_SELF = NTF_SELF,
        NEIGHBOR_CACHE_ENTRY_FLAGS_MASTER = NTF_MASTER,
        NEIGHBOR_CACHE_ENTRY_FLAGS_ROUTER = NTF_ROUTER,
        _NEIGHBOR_CACHE_ENTRY_FLAGS_MAX,
        _NEIGHBOR_CACHE_ENTRY_FLAGS_INVALID = -1,
} NeighborCacheEntryFlags;

struct FdbEntry {
        Network *network;
        NetworkConfigSection *section;

        uint32_t vni;

        int family;
        uint16_t vlan_id;

        struct ether_addr mac_addr;
        union in_addr_union destination_addr;
        NeighborCacheEntryFlags fdb_ntf_flags;

        LIST_FIELDS(FdbEntry, static_fdb_entries);
};

void fdb_entry_free(FdbEntry *fdb_entry);
int fdb_entry_configure(Link *link, FdbEntry *fdb_entry);

DEFINE_NETWORK_SECTION_FUNCTIONS(FdbEntry, fdb_entry_free);

const char* fdb_ntf_flags_to_string(NeighborCacheEntryFlags i) _const_;
NeighborCacheEntryFlags fdb_ntf_flags_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_fdb_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_vlan_id);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_destination);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_vxlan_vni);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_ntf_flags);
