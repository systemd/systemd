/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "conf-parser.h"

typedef struct Manager Manager;

unsigned routes_max(void);

int route_type_from_string(const char *s) _pure_;
const char *route_type_to_string(int t) _const_;

int route_scope_from_string(const char *s);
int route_scope_to_string_alloc(int t, char **ret);

int route_protocol_from_string(const char *s);
int route_protocol_to_string_alloc(int t, char **ret);
int route_protocol_full_from_string(const char *s);
int route_protocol_full_to_string_alloc(int t, char **ret);

int manager_get_route_table_from_string(const Manager *m, const char *table, uint32_t *ret);
int manager_get_route_table_to_string(const Manager *m, uint32_t table, char **ret);

CONFIG_PARSER_PROTOTYPE(config_parse_route_table_names);
