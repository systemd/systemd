/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include <stdint.h>

#include "conf-parser.h"

typedef struct Link Link;

int br_vlan_configure(Link *link, uint16_t pvid, uint32_t *br_vid_bitmap, uint32_t *br_untagged_bitmap);

CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_pvid);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_vlan);
CONFIG_PARSER_PROTOTYPE(config_parse_brvlan_untagged);
