/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-link.h"
#include "networkd-util.h"

typedef struct Manager Manager;
typedef struct Network Network;
typedef struct Request Request;

typedef struct Route {
        Network *network;
        NetworkConfigSection *section;

        Link *link;
        Manager *manager;

        int family;
        int gw_family;
        uint32_t gw_weight;
        int quickack;
        int fast_open_no_cookie;
        int ttl_propagate;

        unsigned char dst_prefixlen;
        unsigned char src_prefixlen;
        unsigned char scope;
        unsigned char protocol;  /* RTPROT_* */
        unsigned char type; /* RTN_* */
        unsigned char tos;
        uint32_t priority; /* note that ip(8) calls this 'metric' */
        uint32_t table;
        uint32_t mtu;
        uint32_t initcwnd;
        uint32_t initrwnd;
        uint32_t advmss;
        unsigned char pref;
        unsigned flags;
        int gateway_onlink;
        uint32_t nexthop_id;

        bool scope_set:1;
        bool table_set:1;
        bool priority_set:1;
        bool protocol_set:1;
        bool pref_set:1;
        bool gateway_from_dhcp_or_ra:1;
        bool removing:1;

        union in_addr_union gw;
        union in_addr_union dst;
        union in_addr_union src;
        union in_addr_union prefsrc;
        OrderedSet *multipath_routes;

        usec_t lifetime;
        sd_event_source *expire;
} Route;

void route_hash_func(const Route *route, struct siphash *state);
int route_compare_func(const Route *a, const Route *b);
bool route_equal(const Route *r1, const Route *r2);
extern const struct hash_ops route_hash_ops;

int route_new(Route **ret);
Route *route_free(Route *route);
DEFINE_NETWORK_SECTION_FUNCTIONS(Route, route_free);
int route_dup(const Route *src, Route **ret);

int route_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg);
int route_remove(const Route *route, Manager *manager, Link *link);

int link_has_route(Link *link, const Route *route);
int manager_find_uplink(Manager *m, int family, Link *exclude, Link **ret);
bool gateway_is_ready(Link *link, int onlink, int family, const union in_addr_union *gw);

int link_drop_routes(Link *link);
int link_drop_foreign_routes(Link *link);

uint32_t link_get_dhcp_route_table(const Link *link);
uint32_t link_get_ipv6_accept_ra_route_table(const Link *link);

int link_request_route(
                Link *link,
                Route *route,
                bool consume_object,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret);
int link_request_static_routes(Link *link, bool only_ipv4);
int request_process_route(Request *req);

int manager_rtnl_process_route(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

int network_add_ipv4ll_route(Network *network);
int network_add_default_route_on_device(Network *network);
void network_drop_invalid_routes(Network *network);

int manager_get_route_table_from_string(const Manager *m, const char *table, uint32_t *ret);
int manager_get_route_table_to_string(const Manager *m, uint32_t table, char **ret);

CONFIG_PARSER_PROTOTYPE(config_parse_gateway);
CONFIG_PARSER_PROTOTYPE(config_parse_preferred_src);
CONFIG_PARSER_PROTOTYPE(config_parse_destination);
CONFIG_PARSER_PROTOTYPE(config_parse_route_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_route_scope);
CONFIG_PARSER_PROTOTYPE(config_parse_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_route_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_route_preference);
CONFIG_PARSER_PROTOTYPE(config_parse_route_protocol);
CONFIG_PARSER_PROTOTYPE(config_parse_route_type);
CONFIG_PARSER_PROTOTYPE(config_parse_tcp_window);
CONFIG_PARSER_PROTOTYPE(config_parse_route_mtu);
CONFIG_PARSER_PROTOTYPE(config_parse_multipath_route);
CONFIG_PARSER_PROTOTYPE(config_parse_tcp_advmss);
CONFIG_PARSER_PROTOTYPE(config_parse_route_table_names);
CONFIG_PARSER_PROTOTYPE(config_parse_route_nexthop);
