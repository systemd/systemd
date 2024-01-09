/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Route Route;

int route_nexthops_set_netlink_message(Link *link, const Route *route, sd_netlink_message *message);
int route_nexthops_read_netlink_message(Route *route, sd_netlink_message *message);

int route_section_verify_nexthops(Route *route);

CONFIG_PARSER_PROTOTYPE(config_parse_gateway);
CONFIG_PARSER_PROTOTYPE(config_parse_route_gateway_onlink);
CONFIG_PARSER_PROTOTYPE(config_parse_route_nexthop);
CONFIG_PARSER_PROTOTYPE(config_parse_multipath_route);
