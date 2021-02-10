/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp6-client.h"

#include "conf-parser.h"
#include "macro.h"

typedef enum DHCP6ClientStartMode {
        DHCP6_CLIENT_START_MODE_NO,
        DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST,
        DHCP6_CLIENT_START_MODE_SOLICIT,
        _DHCP6_CLIENT_START_MODE_MAX,
        _DHCP6_CLIENT_START_MODE_INVALID = -EINVAL,
} DHCP6ClientStartMode;

typedef struct Link Link;
typedef struct Manager Manager;

typedef struct DHCP6DelegatedPrefix {
        struct in6_addr prefix;     /* Prefix assigned to the link */
        struct in6_addr pd_prefix;  /* PD prefix provided by DHCP6 lease */
        Link *link;
} DHCP6DelegatedPrefix;

DHCP6DelegatedPrefix *dhcp6_pd_free(DHCP6DelegatedPrefix *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(DHCP6DelegatedPrefix*, dhcp6_pd_free);

bool link_dhcp6_pd_is_enabled(Link *link);
int dhcp6_pd_remove(Link *link);
int dhcp6_configure(Link *link);
int dhcp6_update_mac(Link *link);
int dhcp6_request_address(Link *link, int ir);
int dhcp6_request_prefix_delegation(Link *link);

int link_serialize_dhcp6_client(Link *link, FILE *f);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_pd_hint);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_mud_url);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_client_start_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_pd_subnet_id);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_pd_token);

const char* dhcp6_client_start_mode_to_string(DHCP6ClientStartMode i) _const_;
DHCP6ClientStartMode dhcp6_client_start_mode_from_string(const char *s) _pure_;
