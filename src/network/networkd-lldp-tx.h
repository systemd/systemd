/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "conf-parser.h"

typedef struct Link Link;

typedef enum LLDPEmit {
        LLDP_EMIT_NO,
        LLDP_EMIT_NEAREST_BRIDGE,
        LLDP_EMIT_NON_TPMR_BRIDGE,
        LLDP_EMIT_CUSTOMER_BRIDGE,
        _LLDP_EMIT_MAX,
        _LLDP_EMIT_INVALID = -EINVAL,
} LLDPEmit;

bool link_lldp_emit_enabled(Link *link);
int link_lldp_emit_start(Link *link);
void link_lldp_emit_stop(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_lldp_emit);
CONFIG_PARSER_PROTOTYPE(config_parse_lldp_mud);
