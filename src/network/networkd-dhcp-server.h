/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-util.h"

typedef struct Link Link;

int dhcp4_server_configure(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_sip);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_pop3_servers);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_smtp_servers);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_lpr_servers);
