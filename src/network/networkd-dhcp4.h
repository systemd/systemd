/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;

typedef enum DHCPClientIdentifier {
        DHCP_CLIENT_ID_MAC,
        DHCP_CLIENT_ID_DUID,
        /* The following option may not be good for RFC regarding DHCP (3315 and 4361).
         * But some setups require this. E.g., Sky Broadband, the second largest provider in the UK
         * requires the client id to be set to a custom string, reported at
         * https://github.com/systemd/systemd/issues/7828 */
        DHCP_CLIENT_ID_DUID_ONLY,
        _DHCP_CLIENT_ID_MAX,
        _DHCP_CLIENT_ID_INVALID = -1,
} DHCPClientIdentifier;

void dhcp4_release_old_lease(Link *link);
int dhcp4_configure(Link *link);
int dhcp4_set_client_identifier(Link *link);
int dhcp4_set_promote_secondaries(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_client_identifier);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_black_listed_ip_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_max_attempts);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_user_class);
