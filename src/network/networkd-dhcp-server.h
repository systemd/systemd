/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Network Network;
typedef struct Request Request;

void network_adjust_dhcp_server(Network *network);

int link_request_dhcp_server_address(Link *link);
int link_request_dhcp_server(Link *link);
int dhcp_server_process_request(Request *req, Link *link, void *userdata);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_relay_agent_suboption);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_emit);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_address);
