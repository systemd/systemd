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

int bridge_vlan_append_info(
                const Link * link,
                sd_netlink_message *req,
                uint16_t pvid,
                const uint32_t *br_vid_bitmap,
                const uint32_t *br_untagged_bitmap);

CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_pvid);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_vlan);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_untagged);
