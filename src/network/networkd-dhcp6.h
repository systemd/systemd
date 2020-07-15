/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-dhcp6-client.h"

#include "conf-parser.h"
#include "macro.h"

typedef enum DHCP6ClientStartMode {
        DHCP6_CLIENT_START_MODE_NO,
        DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST,
        DHCP6_CLIENT_START_MODE_SOLICIT,
        _DHCP6_CLIENT_START_MODE_MAX,
        _DHCP6_CLIENT_START_MODE_INVALID = -1,
} DHCP6ClientStartMode;

typedef struct Link Link;
typedef struct Manager Manager;

bool dhcp6_get_prefix_delegation(Link *link);
int dhcp6_request_prefix_delegation(Link *link);
int dhcp6_configure(Link *link);
int dhcp6_request_address(Link *link, int ir);
int dhcp6_lease_pd_prefix_lost(sd_dhcp6_client *client, Link* link);
int dhcp6_prefix_remove(Manager *m, struct in6_addr *addr);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_pd_hint);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_mud_url);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_delegated_prefix_token);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_client_start_mode);

const char* dhcp6_client_start_mode_to_string(DHCP6ClientStartMode i) _const_;
DHCP6ClientStartMode dhcp6_client_start_mode_from_string(const char *s) _pure_;
