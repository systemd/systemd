/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-util.h"

typedef struct Link Link;

typedef enum DHCPRawOption {
        DHCP_RAW_OPTION_DATA_UINT8,
        DHCP_RAW_OPTION_DATA_UINT16,
        DHCP_RAW_OPTION_DATA_UINT32,
        DHCP_RAW_OPTION_DATA_STRING,
        DHCP_RAW_OPTION_DATA_IPV4ADDRESS,
        _DHCP_RAW_OPTION_DATA_MAX,
        _DHCP_RAW_OPTION_DATA_INVALID,
} DHCPRawOption;

const char *dhcp_raw_option_data_type_to_string(DHCPRawOption d) _const_;
DHCPRawOption dhcp_raw_option_data_type_from_string(const char *d) _pure_;

int dhcp4_server_configure(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_sip);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_raw_option_data);
