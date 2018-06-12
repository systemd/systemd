/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "networkd-link.h"

typedef enum LLDPEmit {
        LLDP_EMIT_NO,
        LLDP_EMIT_NEAREST_BRIDGE,
        LLDP_EMIT_NON_TPMR_BRIDGE,
        LLDP_EMIT_CUSTOMER_BRIDGE,
        _LLDP_EMIT_MAX,
} LLDPEmit;

int link_lldp_emit_start(Link *link);
void link_lldp_emit_stop(Link *link);

int config_parse_lldp_emit(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
