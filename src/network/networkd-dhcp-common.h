/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>

#include "conf-parser.h"
#include "dhcp-identifier.h"
#include "in-addr-util.h"
#include "set.h"
#include "time-util.h"

/* Special values for *_uplink_index. */
#define UPLINK_INDEX_AUTO  0 /* uplink will be selected automatically */
#define UPLINK_INDEX_NONE -1 /* uplink will not be selected automatically */
#define UPLINK_INDEX_SELF -2 /* the interface itself is uplink */

#define DHCP_ROUTE_METRIC 1024
#define DHCP6PD_ROUTE_METRIC 256

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Network Network;

typedef enum DHCPUseDomains {
        DHCP_USE_DOMAINS_NO,
        DHCP_USE_DOMAINS_YES,
        DHCP_USE_DOMAINS_ROUTE,
        _DHCP_USE_DOMAINS_MAX,
        _DHCP_USE_DOMAINS_INVALID = -EINVAL,
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
        bool set;
} DUID;

uint32_t link_get_dhcp4_route_table(Link *link);
uint32_t link_get_ipv6_accept_ra_route_table(Link *link);

bool link_dhcp_enabled(Link *link, int family);
static inline bool link_dhcp4_enabled(Link *link) {
        return link_dhcp_enabled(link, AF_INET);
}
static inline bool link_dhcp6_enabled(Link *link) {
        return link_dhcp_enabled(link, AF_INET6);
}

void network_adjust_dhcp(Network *network);

const DUID *link_get_duid(Link *link, int family);
static inline const DUID *link_get_dhcp4_duid(Link *link) {
        return link_get_duid(link, AF_INET);
}
static inline const DUID *link_get_dhcp6_duid(Link *link) {
        return link_get_duid(link, AF_INET6);
}

int dhcp_configure_duid(Link *link, const DUID *duid);
int manager_request_product_uuid(Manager *m);

bool address_is_filtered(int family, const union in_addr_union *address, uint8_t prefixlen, Set *allow_list, Set *deny_list);
static inline bool in4_address_is_filtered(const struct in_addr *address, Set *allow_list, Set *deny_list) {
        return address_is_filtered(AF_INET, &(union in_addr_union) { .in = *address }, 32, allow_list, deny_list);
}
static inline bool in6_prefix_is_filtered(const struct in6_addr *prefix, uint8_t prefixlen, Set *allow_list, Set *deny_list) {
        return address_is_filtered(AF_INET6, &(union in_addr_union) { .in6 = *prefix }, prefixlen, allow_list, deny_list);
}

const char* dhcp_use_domains_to_string(DHCPUseDomains p) _const_;
DHCPUseDomains dhcp_use_domains_from_string(const char *s) _pure_;

const char *dhcp_option_data_type_to_string(DHCPOptionDataType d) _const_;
DHCPOptionDataType dhcp_option_data_type_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_or_ra_route_metric);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_use_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_use_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_use_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_iaid);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_or_ra_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_user_or_vendor_class);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_send_option);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_request_options);
CONFIG_PARSER_PROTOTYPE(config_parse_duid_type);
CONFIG_PARSER_PROTOTYPE(config_parse_manager_duid_type);
CONFIG_PARSER_PROTOTYPE(config_parse_network_duid_type);
CONFIG_PARSER_PROTOTYPE(config_parse_duid_rawdata);
CONFIG_PARSER_PROTOTYPE(config_parse_manager_duid_rawdata);
CONFIG_PARSER_PROTOTYPE(config_parse_network_duid_rawdata);
CONFIG_PARSER_PROTOTYPE(config_parse_uplink);
