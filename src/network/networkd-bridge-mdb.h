/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Network Network;

typedef struct BridgeMDB {
        Network *network;
        ConfigSection *section;

        int family;
        union in_addr_union group_addr;
        uint16_t vlan_id;
} BridgeMDB;

BridgeMDB *bridge_mdb_free(BridgeMDB *mdb);

void network_drop_invalid_bridge_mdb_entries(Network *network);

int link_request_static_bridge_mdb(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_mdb_group_address);
CONFIG_PARSER_PROTOTYPE(config_parse_mdb_vlan_id);
