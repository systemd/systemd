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

        LIST_FIELDS(MdbEntry, static_mdb_entries);
};

int mdb_entry_verify(MdbEntry *mdb_entry);
MdbEntry *mdb_entry_free(MdbEntry *mdb_entry);
int mdb_entry_configure(Link *link, MdbEntry *mdb_entry);

DEFINE_NETWORK_SECTION_FUNCTIONS(MdbEntry, mdb_entry_free);

CONFIG_PARSER_PROTOTYPE(config_parse_mdb_group_address);
CONFIG_PARSER_PROTOTYPE(config_parse_mdb_vlan_id);
