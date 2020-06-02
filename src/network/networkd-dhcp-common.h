/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "dhcp-identifier.h"
#include "time-util.h"

#define DHCP_ROUTE_METRIC 1024

typedef enum DHCPUseDomains {
        DHCP_USE_DOMAINS_NO,
        DHCP_USE_DOMAINS_YES,
        DHCP_USE_DOMAINS_ROUTE,
        _DHCP_USE_DOMAINS_MAX,
        _DHCP_USE_DOMAINS_INVALID = -1,
} DHCPUseDomains;

typedef enum DHCPOptionDataType {
        DHCP_OPTION_DATA_UINT8,
        DHCP_OPTION_DATA_UINT16,
        DHCP_OPTION_DATA_UINT32,
        DHCP_OPTION_DATA_STRING,
        DHCP_OPTION_DATA_IPV4ADDRESS,
        DHCP_OPTION_DATA_IPV6ADDRESS,
        _DHCP_OPTION_DATA_MAX,
        _DHCP_OPTION_DATA_INVALID,
} DHCPOptionDataType;

typedef struct DUID {
        /* Value of Type in [DHCP] section */
        DUIDType type;

        uint8_t raw_data_len;
        uint8_t raw_data[MAX_DUID_LEN];
        usec_t llt_time;
} DUID;

const char* dhcp_use_domains_to_string(DHCPUseDomains p) _const_;
DHCPUseDomains dhcp_use_domains_from_string(const char *s) _pure_;

const char *dhcp_option_data_type_to_string(DHCPOptionDataType d) _const_;
DHCPOptionDataType dhcp_option_data_type_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_route_metric);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_use_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_use_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_use_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_iaid);
CONFIG_PARSER_PROTOTYPE(config_parse_section_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_user_class);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_vendor_class);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_send_option);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_request_options);
