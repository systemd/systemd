/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

typedef enum LLDPMode {
        LLDP_MODE_NO = 0,
        LLDP_MODE_YES = 1,
        LLDP_MODE_ROUTERS_ONLY = 2,
        _LLDP_MODE_MAX,
        _LLDP_MODE_INVALID = -EINVAL,
} LLDPMode;

int link_lldp_rx_configure(Link *link);

const char* lldp_mode_to_string(LLDPMode m) _const_;
LLDPMode lldp_mode_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_lldp_mode);
