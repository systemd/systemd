/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include <inttypes.h>

#include "sd-netlink.h"

#include "conf-parser.h"

#define BRIDGE_VLAN_BITMAP_MAX 4096
#define BRIDGE_VLAN_BITMAP_LEN (BRIDGE_VLAN_BITMAP_MAX / 32)

typedef struct Link Link;
typedef struct Network Network;

void network_adjust_bridge_vlan(Network *network);

int bridge_vlan_set_message(Link *link, sd_netlink_message *m);

CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_pvid);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_vlan);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_untagged);
