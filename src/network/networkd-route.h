/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"

typedef struct Route Route;
typedef struct NetworkConfigSection NetworkConfigSection;

#include "networkd-network.h"

struct Route {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        int family;
        int quickack;

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
        unsigned char pref;
        unsigned flags;

        union in_addr_union gw;
        union in_addr_union dst;
        union in_addr_union src;
        union in_addr_union prefsrc;

        usec_t lifetime;
        sd_event_source *expire;

        LIST_FIELDS(Route, routes);
};

int route_new_static(Network *network, const char *filename, unsigned section_line, Route **ret);
int route_new(Route **ret);
void route_free(Route *route);
int route_configure(Route *route, Link *link, sd_netlink_message_handler_t callback);
int route_remove(Route *route, Link *link, sd_netlink_message_handler_t callback);

int route_get(Link *link, int family, const union in_addr_union *dst, unsigned char dst_prefixlen, unsigned char tos, uint32_t priority, uint32_t table, Route **ret);
int route_add(Link *link, int family, const union in_addr_union *dst, unsigned char dst_prefixlen, unsigned char tos, uint32_t priority, uint32_t table, Route **ret);
int route_add_foreign(Link *link, int family, const union in_addr_union *dst, unsigned char dst_prefixlen, unsigned char tos, uint32_t priority, uint32_t table, Route **ret);
void route_update(Route *route, const union in_addr_union *src, unsigned char src_prefixlen, const union in_addr_union *gw, const union in_addr_union *prefsrc, unsigned char scope, unsigned char protocol, unsigned char type);
bool route_equal(Route *r1, Route *r2);

int route_expire_handler(sd_event_source *s, uint64_t usec, void *userdata);

DEFINE_TRIVIAL_CLEANUP_FUNC(Route*, route_free);

CONFIG_PARSER_PROTOTYPE(config_parse_gateway);
CONFIG_PARSER_PROTOTYPE(config_parse_preferred_src);
CONFIG_PARSER_PROTOTYPE(config_parse_destination);
CONFIG_PARSER_PROTOTYPE(config_parse_route_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_route_scope);
CONFIG_PARSER_PROTOTYPE(config_parse_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_gateway_onlink);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_route_preference);
CONFIG_PARSER_PROTOTYPE(config_parse_route_protocol);
CONFIG_PARSER_PROTOTYPE(config_parse_route_type);
CONFIG_PARSER_PROTOTYPE(config_parse_tcp_window);
CONFIG_PARSER_PROTOTYPE(config_parse_quickack);
CONFIG_PARSER_PROTOTYPE(config_parse_route_mtu);
