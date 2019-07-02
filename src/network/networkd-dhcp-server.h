/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;

int dhcp4_server_configure(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_ntp);
