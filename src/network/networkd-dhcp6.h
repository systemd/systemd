/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "in-addr-util.h"
#include "macro.h"

typedef enum DHCP6ClientStartMode {
        DHCP6_CLIENT_START_MODE_NO,
        DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST,
        DHCP6_CLIENT_START_MODE_SOLICIT,
        _DHCP6_CLIENT_START_MODE_MAX,
        _DHCP6_CLIENT_START_MODE_INVALID = -EINVAL,
} DHCP6ClientStartMode;

typedef struct Link Link;
typedef struct Request Request;

bool link_dhcp6_with_address_enabled(Link *link);
bool link_dhcp6_pd_is_enabled(Link *link);
int dhcp6_pd_remove(Link *link, bool only_marked);
int dhcp6_update_mac(Link *link);
int dhcp6_start(Link *link);
int dhcp6_start_on_ra(Link *link, bool information_request);
int dhcp6_request_prefix_delegation(Link *link);

int request_process_dhcp6_client(Request *req);
int link_request_dhcp6_client(Link *link);

int link_serialize_dhcp6_client(Link *link, FILE *f);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_pd_prefix_hint);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_mud_url);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_client_start_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_pd_subnet_id);

const char* dhcp6_client_start_mode_to_string(DHCP6ClientStartMode i) _const_;
DHCP6ClientStartMode dhcp6_client_start_mode_from_string(const char *s) _pure_;
