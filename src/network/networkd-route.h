/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "macro.h"

typedef struct Route Route;
typedef struct NetworkConfigSection NetworkConfigSection;

#include "networkd-network.h"
#include "networkd-util.h"

struct Route {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        int family;
        int quickack;
        int fast_open_no_cookie;
        int ttl_propagate;

        unsigned char dst_prefixlen;
        unsigned char src_prefixlen;
        unsigned char scope;
        bool scope_set;
        unsigned char protocol;  /* RTPROT_* */
        unsigned char type; /* RTN_* */
        unsigned char tos;
        uint32_t priority; /* note that ip(8) calls this 'metric' */
        uint32_t table;
        bool table_set;
        uint32_t mtu;
        uint32_t initcwnd;
        uint32_t initrwnd;
        unsigned char pref;
        unsigned flags;
        int gateway_onlink;

        union in_addr_union gw;
        union in_addr_union dst;
        union in_addr_union src;
        union in_addr_union prefsrc;

        usec_t lifetime;
        sd_event_source *expire;

        LIST_FIELDS(Route, routes);
};

extern const struct hash_ops route_hash_ops;

int route_new(Route **ret);
void route_free(Route *route);
int route_configure(Route *route, Link *link, link_netlink_message_handler_t callback);
int route_remove(Route *route, Link *link, link_netlink_message_handler_t callback);

int route_get(Link *link, Route *in, Route **ret);
int route_add(Link *link, Route *in, Route **ret);
int route_add_foreign(Link *link, Route *in, Route **ret);
bool route_equal(Route *r1, Route *r2);

int route_expire_handler(sd_event_source *s, uint64_t usec, void *userdata);
int route_section_verify(Route *route, Network *network);

DEFINE_NETWORK_SECTION_FUNCTIONS(Route, route_free);

int network_add_ipv4ll_route(Network *network);
int network_add_default_route_on_device(Network *network);

const char* route_type_to_string(int t) _const_;
int route_type_from_string(const char *s) _pure_;

#define ROUTE_SCOPE_STR_MAX CONST_MAX(DECIMAL_STR_MAX(int), STRLEN("nowhere") + 1)
const char *format_route_scope(int scope, char *buf, size_t size);

#define ROUTE_TABLE_STR_MAX CONST_MAX(DECIMAL_STR_MAX(int), STRLEN("default") + 1)
const char *format_route_table(int table, char *buf, size_t size);

#define ROUTE_PROTOCOL_STR_MAX CONST_MAX(DECIMAL_STR_MAX(int), STRLEN("redirect") + 1)
const char *format_route_protocol(int protocol, char *buf, size_t size);

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
CONFIG_PARSER_PROTOTYPE(config_parse_fast_open_no_cookie);
CONFIG_PARSER_PROTOTYPE(config_parse_route_ttl_propagate);
CONFIG_PARSER_PROTOTYPE(config_parse_route_mtu);
