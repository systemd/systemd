/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;

int link_lldp_tx_configure(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_lldp_multicast_mode);
