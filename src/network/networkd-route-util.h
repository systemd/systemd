/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

unsigned routes_max(void);

bool route_type_is_reject(uint8_t type);
bool route_is_reject(const Route *route);

bool link_find_default_gateway(Link *link, int family, Route **gw);
static inline bool link_has_default_gateway(Link *link, int family) {
        return link_find_default_gateway(link, family, NULL);
}

int manager_find_uplink(Manager *m, int family, Link *exclude, Link **ret);

bool gateway_is_ready(Link *link, bool onlink, int family, const union in_addr_union *gw);

int link_address_is_reachable(
                Link *link,
                int family,
                const union in_addr_union *address,
                const union in_addr_union *prefsrc, /* optional */
                Address **ret);

int manager_address_is_reachable(
                Manager *manager,
                int family,
                const union in_addr_union *address,
                const union in_addr_union *prefsrc, /* optional */
                Address **ret);

DECLARE_STRING_TABLE_LOOKUP(route_type, int);

DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(route_scope, int);
DECLARE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(route_scope, int);

DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(route_protocol, int);
DECLARE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(route_protocol, int);
DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(route_protocol_full, int);
DECLARE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(route_protocol_full, int);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(route_flags, uint32_t);

int manager_get_route_table_from_string(const Manager *m, const char *s, uint32_t *ret);
int manager_get_route_table_to_string(const Manager *m, uint32_t table, bool append_num, char **ret);

CONFIG_PARSER_PROTOTYPE(config_parse_route_table_names);
