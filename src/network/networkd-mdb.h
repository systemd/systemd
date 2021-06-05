/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Network Network;
typedef struct Link Link;

typedef struct MdbEntry {
        Network *network;
        NetworkConfigSection *section;

        int family;
        union in_addr_union group_addr;
        uint16_t vlan_id;
} MdbEntry;

MdbEntry *mdb_entry_free(MdbEntry *mdb_entry);

void network_drop_invalid_mdb_entries(Network *network);

int link_set_bridge_mdb(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_mdb_group_address);
CONFIG_PARSER_PROTOTYPE(config_parse_mdb_vlan_id);
