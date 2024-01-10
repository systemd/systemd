/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "hash-funcs.h"
#include "in-addr-util.h"
#include "macro.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Route Route;

typedef struct RouteNextHop {
        int family; /* used in RTA_VIA (IPv4 only) */
        union in_addr_union gw; /* RTA_GATEWAY or RTA_VIA (IPv4 only) */
        uint32_t weight; /* rtnh_hops */
        int ifindex; /* RTA_OIF(u32) or rtnh_ifindex */
        char *ifname; /* only used by Route object owned by Network object */
        /* unsupported attributes: RTA_FLOW (IPv4 only), RTA_ENCAP_TYPE, RTA_ENCAP. */
} RouteNextHop;

#define ROUTE_NEXTHOP_NULL ((const RouteNextHop) {})

RouteNextHop* route_nexthop_free(RouteNextHop *nh);
DEFINE_TRIVIAL_CLEANUP_FUNC(RouteNextHop*, route_nexthop_free);

void route_nexthops_done(Route *route);

int route_nexthops_copy(const Route *src, const RouteNextHop *nh, Route *dest);

void route_nexthops_hash_func(const Route *route, struct siphash *state);
int route_nexthops_compare_func(const Route *a, const Route *b);

int route_nexthops_to_string(const Route *route, char **ret);

int route_adjust_nexthops(Route *route, Link *link);

int route_nexthop_get_link(Manager *manager, const RouteNextHop *nh, Link **ret);
int route_nexthops_is_ready_to_configure(const Route *route, Manager *manager);

int route_nexthops_set_netlink_message(const Route *route, sd_netlink_message *message);
int route_nexthops_read_netlink_message(Route *route, sd_netlink_message *message);

int route_section_verify_nexthops(Route *route);

CONFIG_PARSER_PROTOTYPE(config_parse_gateway);
CONFIG_PARSER_PROTOTYPE(config_parse_route_gateway_onlink);
CONFIG_PARSER_PROTOTYPE(config_parse_route_nexthop);
CONFIG_PARSER_PROTOTYPE(config_parse_multipath_route);
