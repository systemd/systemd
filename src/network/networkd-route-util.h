/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Address Address;

unsigned routes_max(void);

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

int route_type_from_string(const char *s) _pure_;
const char *route_type_to_string(int t) _const_;

int route_scope_from_string(const char *s);
int route_scope_to_string_alloc(int t, char **ret);

int route_protocol_from_string(const char *s);
int route_protocol_to_string_alloc(int t, char **ret);
int route_protocol_full_from_string(const char *s);
int route_protocol_full_to_string_alloc(int t, char **ret);

int route_flags_to_string_alloc(uint32_t flags, char **ret);

int manager_get_route_table_from_string(const Manager *m, const char *table, uint32_t *ret);
int manager_get_route_table_to_string(const Manager *m, uint32_t table, char **ret);

CONFIG_PARSER_PROTOTYPE(config_parse_route_table_names);
