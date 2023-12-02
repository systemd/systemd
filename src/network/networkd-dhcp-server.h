/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "set.h"

typedef struct Link Link;
typedef struct Network Network;

int network_adjust_dhcp_server(Network *network, Set **addresses);

int link_request_dhcp_server(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_relay_agent_suboption);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_emit);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_ipv6_only_preferred);
