/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-link.h"
#include "networkd-route-metric.h"
#include "networkd-route-nexthop.h"
#include "networkd-util.h"

typedef struct Manager Manager;
typedef struct Network Network;
typedef struct Request Request;
typedef struct Route Route;
typedef struct Wireguard Wireguard;

typedef int (*route_netlink_handler_t)(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                Route *route);

struct Route {
        Manager *manager;
        Network *network;
        Wireguard *wireguard;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;
        union in_addr_union provider; /* DHCP server or router address */

        /* rtmsg header */
        int family;
        unsigned char dst_prefixlen;
        unsigned char src_prefixlen; /* IPv6 only */
        unsigned char tos; /* IPv4 only */
        unsigned char protocol;  /* RTPROT_* */
        unsigned char scope; /* IPv4 only */
        unsigned char type; /* RTN_*, e.g. RTN_LOCAL, RTN_UNREACHABLE */
        unsigned flags; /* e.g. RTNH_F_ONLINK */

        /* attributes */
        union in_addr_union dst; /* RTA_DST */
        union in_addr_union src; /* RTA_SRC (IPv6 only) */
        uint32_t priority; /* RTA_PRIORITY, note that ip(8) calls this 'metric' */
        union in_addr_union prefsrc; /* RTA_PREFSRC */
        uint32_t table; /* RTA_TABLE, also used in rtmsg header */
        uint8_t pref; /* RTA_PREF (IPv6 only) */

        /* nexthops */
        RouteNextHop nexthop; /* RTA_OIF, and RTA_GATEWAY or RTA_VIA (IPv4 only) */
        OrderedSet *nexthops; /* RTA_MULTIPATH */
        uint32_t nexthop_id; /* RTA_NH_ID */

        /* metrics (RTA_METRICS) */
        RouteMetric metric;

        /* This is an absolute point in time, and NOT a timespan/duration.
         * Must be specified with clock_boottime_or_monotonic(). */
        usec_t lifetime_usec; /* RTA_EXPIRES (IPv6 only) */
        /* Used when kernel does not support RTA_EXPIRES attribute. */
        sd_event_source *expire;
        bool expiration_managed_by_kernel:1; /* RTA_CACHEINFO has nonzero rta_expires */

        /* Only used by conf persers and route_section_verify(). */
        bool scope_set:1;
        bool table_set:1;
        bool priority_set:1;
        bool protocol_set:1;
        bool pref_set:1;
        bool gateway_from_dhcp_or_ra:1;
        int gateway_onlink;
};

extern const struct hash_ops route_hash_ops;

Route* route_free(Route *route);
DEFINE_SECTION_CLEANUP_FUNCTIONS(Route, route_free);

int route_new(Route **ret);
int route_new_static(Network *network, const char *filename, unsigned section_line, Route **ret);
int route_dup(const Route *src, const RouteNextHop *nh, Route **ret);

bool route_type_is_reject(const Route *route);

int route_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, Route *route, const char *error_msg);
int route_remove(Route *route, Manager *manager);
int route_remove_and_cancel(Route *route, Manager *manager);

int route_get(Manager *manager, const Route *route, Route **ret);

int link_drop_routes(Link *link, bool foreign);
static inline int link_drop_managed_routes(Link *link) {
        return link_drop_routes(link, false);
}
static inline int link_drop_foreign_routes(Link *link) {
        return link_drop_routes(link, true);
}
int link_foreignize_routes(Link *link);

int link_request_route(
                Link *link,
                const Route *route,
                unsigned *message_counter,
                route_netlink_handler_t netlink_handler,
                Request **ret);
int link_request_static_routes(Link *link, bool only_ipv4);

int manager_rtnl_process_route(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

int network_add_ipv4ll_route(Network *network);
int network_add_default_route_on_device(Network *network);
void network_drop_invalid_routes(Network *network);
int route_section_verify(Route *route);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(Route, route);
void manager_mark_routes(Manager *manager, Link *link, NetworkConfigSource source);

CONFIG_PARSER_PROTOTYPE(config_parse_preferred_src);
CONFIG_PARSER_PROTOTYPE(config_parse_destination);
CONFIG_PARSER_PROTOTYPE(config_parse_route_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_route_scope);
CONFIG_PARSER_PROTOTYPE(config_parse_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_route_preference);
CONFIG_PARSER_PROTOTYPE(config_parse_route_protocol);
CONFIG_PARSER_PROTOTYPE(config_parse_route_type);
