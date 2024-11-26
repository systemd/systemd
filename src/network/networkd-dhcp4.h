/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Network Network;

typedef enum DHCPClientIdentifier {
        DHCP_CLIENT_ID_MAC,
        DHCP_CLIENT_ID_DUID,
        _DHCP_CLIENT_ID_MAX,
        _DHCP_CLIENT_ID_INVALID = -EINVAL,
} DHCPClientIdentifier;

void network_adjust_dhcp4(Network *network);
int dhcp4_update_mac(Link *link);
int dhcp4_update_ipv6_connectivity(Link *link);
int dhcp4_start_full(Link *link, bool set_ipv6_connectivity);
static inline int dhcp4_start(Link *link) {
        return dhcp4_start_full(link, true);
}
int dhcp4_renew(Link *link);
int dhcp4_lease_lost(Link *link);
int dhcp4_check_ready(Link *link);

int link_request_dhcp4_client(Link *link);
int link_drop_dhcp4_config(Link *link, Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_client_identifier);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_max_attempts);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_ip_service_type);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_socket_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_mud_url);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_fallback_lease_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_label);
