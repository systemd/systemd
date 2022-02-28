/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Network Network;

typedef enum DHCPClientIdentifier {
        DHCP_CLIENT_ID_MAC,
        DHCP_CLIENT_ID_DUID,
        /* The following option may not be good for RFC regarding DHCP (3315 and 4361).
         * But some setups require this. E.g., Sky Broadband, the second largest provider in the UK
         * requires the client id to be set to a custom string, reported at
         * https://github.com/systemd/systemd/issues/7828 */
        DHCP_CLIENT_ID_DUID_ONLY,
        _DHCP_CLIENT_ID_MAX,
        _DHCP_CLIENT_ID_INVALID = -EINVAL,
} DHCPClientIdentifier;

void network_adjust_dhcp4(Network *network);
int dhcp4_update_mac(Link *link);
int dhcp4_start(Link *link);
int dhcp4_lease_lost(Link *link);
int dhcp4_check_ready(Link *link);

int link_request_dhcp4_client(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_client_identifier);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_max_attempts);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_ip_service_type);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_mud_url);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_fallback_lease_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_label);
