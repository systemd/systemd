/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include "conf-parser.h"
#include "list.h"
#include "macro.h"

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

int fdb_entry_new_static(Network *network, const char *filename, unsigned section_line, FdbEntry **ret);
void fdb_entry_free(FdbEntry *fdb_entry);
int fdb_entry_configure(Link *link, FdbEntry *fdb_entry);

DEFINE_TRIVIAL_CLEANUP_FUNC(FdbEntry *, fdb_entry_free);

CONFIG_PARSER_PROTOTYPE(config_parse_fdb_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_fdb_vlan_id);
