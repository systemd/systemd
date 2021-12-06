/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-dhcp-lease.h"
#include "sd-dhcp6-lease.h"

#include "conf-parser.h"

typedef struct Link Link;

bool link_dhcp_pd_is_enabled(Link *link);
bool dhcp_pd_is_uplink(Link *link, Link *target, bool accept_auto);
int dhcp_pd_find_uplink(Link *link, Link **ret);
bool dhcp4_lease_has_pd_prefix(sd_dhcp_lease *lease);
bool dhcp6_lease_has_pd_prefix(sd_dhcp6_lease *lease);
int dhcp_pd_remove(Link *link, bool only_marked);
int dhcp_request_prefix_delegation(Link *link);
int dhcp4_pd_prefix_acquired(Link *uplink);
int dhcp6_pd_prefix_acquired(Link *uplink);
void dhcp_pd_prefix_lost(Link *uplink);
void dhcp4_pd_prefix_lost(Link *uplink);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_pd_subnet_id);
