/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include <inttypes.h>
#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "vlan-util.h"

#define BRIDGE_VLAN_BITMAP_MAX 4096
#define BRIDGE_VLAN_BITMAP_LEN (BRIDGE_VLAN_BITMAP_MAX / 32)

#define BRIDGE_VLAN_KEEP_PVID   UINT16_MAX
#define BRIDGE_VLAN_REMOVE_PVID (UINT16_MAX - 1)
assert_cc(BRIDGE_VLAN_REMOVE_PVID > VLANID_MAX);

typedef struct Link Link;
typedef struct Network Network;

void network_adjust_bridge_vlan(Network *network);

int bridge_vlan_set_message(Link *link, sd_netlink_message *m, bool is_set);

int link_update_bridge_vlan(Link *link, sd_netlink_message *m);

CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_id);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_id_range);
