/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "conf-parser.h"

typedef struct Link Link;

typedef enum LLDPMode {
        LLDP_MODE_NO = 0,
        LLDP_MODE_YES = 1,
        LLDP_MODE_ROUTERS_ONLY = 2,
        _LLDP_MODE_MAX,
        _LLDP_MODE_INVALID = -1,
} LLDPMode;

bool link_lldp_rx_enabled(Link *link);
int link_lldp_rx_configure(Link *link);
int link_update_lldp(Link *link);
int link_lldp_save(Link *link);

const char* lldp_mode_to_string(LLDPMode m) _const_;
LLDPMode lldp_mode_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_lldp_mode);
