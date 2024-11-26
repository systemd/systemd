/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-dhcp-lease.h"
#include "sd-dhcp6-lease.h"

#include "conf-parser.h"

typedef struct Address Address;
typedef struct Link Link;
typedef struct Network Network;

bool link_dhcp_pd_is_enabled(Link *link);
bool dhcp_pd_is_uplink(Link *link, Link *target, bool accept_auto);
int dhcp_pd_find_uplink(Link *link, Link **ret);
int dhcp_pd_remove(Link *link, bool only_marked);
int dhcp_request_prefix_delegation(Link *link);
int link_drop_dhcp_pd_config(Link *link, Network *network);
int dhcp4_pd_prefix_acquired(Link *uplink);
int dhcp6_pd_prefix_acquired(Link *uplink);
void dhcp4_pd_prefix_lost(Link *uplink);
void dhcp6_pd_prefix_lost(Link *uplink);
int dhcp_pd_reconfigure_address(Address *address, Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_pd_subnet_id);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_pd_prefix_route_type);
