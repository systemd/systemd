/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include "conf-parser.h"

#define BRIDGE_VLAN_BITMAP_MAX 4096
#define BRIDGE_VLAN_BITMAP_LEN (BRIDGE_VLAN_BITMAP_MAX / 32)

typedef struct Link Link;

int link_set_bridge_vlan(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_pvid);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_vlan);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_untagged);
