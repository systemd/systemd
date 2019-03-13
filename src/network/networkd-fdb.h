/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include "conf-parser.h"
#include "list.h"
#include "macro.h"
#include "networkd-util.h"

typedef struct Network Network;
typedef struct FdbEntry FdbEntry;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

struct FdbEntry {
        Network *network;
        NetworkConfigSection *section;

        struct ether_addr *mac_addr;
        uint16_t vlan_id;

        LIST_FIELDS(FdbEntry, static_fdb_entries);
};

void fdb_entry_free(FdbEntry *fdb_entry);
int fdb_entry_configure(Link *link, FdbEntry *fdb_entry);

DEFINE_NETWORK_SECTION_FUNCTIONS(FdbEntry, fdb_entry_free);

CONFIG_PARSER_PROTOTYPE(config_parse_fdb_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_vlan_id);
