/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "conf-parser.h"

typedef struct Link Link;

bool link_dhcp6_pd_is_enabled(Link *link);
bool dhcp6_pd_is_uplink(Link *link, Link *target, bool accept_auto);
int dhcp6_pd_find_uplink(Link *link, Link **ret);
bool dhcp6_lease_has_pd_prefix(sd_dhcp6_lease *lease);
int dhcp6_pd_remove(Link *link, bool only_marked);
int dhcp6_request_prefix_delegation(Link *link);
int dhcp6_pd_prefix_acquired(Link *dhcp6_link);
void dhcp6_pd_prefix_lost(Link *dhcp6_link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_pd_subnet_id);
