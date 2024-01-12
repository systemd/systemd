/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct MultipathRoute MultipathRoute;
typedef struct Route Route;

int multipath_route_get_link(Manager *manager, const MultipathRoute *m, Link **ret);
int route_nexthops_is_ready_to_configure(const Route *route, Link *link);

int route_nexthops_to_string(const Route *route, char **ret);

int route_nexthops_set_netlink_message(Link *link, const Route *route, sd_netlink_message *message);
int route_nexthops_read_netlink_message(Route *route, sd_netlink_message *message);

int route_section_verify_nexthops(Route *route);

CONFIG_PARSER_PROTOTYPE(config_parse_gateway);
CONFIG_PARSER_PROTOTYPE(config_parse_route_gateway_onlink);
CONFIG_PARSER_PROTOTYPE(config_parse_route_nexthop);
CONFIG_PARSER_PROTOTYPE(config_parse_multipath_route);
