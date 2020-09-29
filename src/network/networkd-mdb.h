/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "list.h"
#include "macro.h"
#include "networkd-util.h"

typedef struct Network Network;
typedef struct MdbEntry MdbEntry;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

struct MdbEntry {
        Network *network;
        NetworkConfigSection *section;

        int family;
        union in_addr_union group_addr;
        uint16_t vlan_id;
};

MdbEntry *mdb_entry_free(MdbEntry *mdb_entry);

void network_verify_mdb_entries(Network *network);

int link_set_bridge_mdb(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_mdb_group_address);
CONFIG_PARSER_PROTOTYPE(config_parse_mdb_vlan_id);
