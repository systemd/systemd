/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "analyze-verify-util.h"
#include "bus-util.h"
#include "json.h"
#include "pager.h"
#include "time-util.h"
#include "unit-file.h"

typedef enum DotMode {
        DEP_ALL,
        DEP_ORDER,
        DEP_REQUIRE,
} DotMode;

extern DotMode arg_dot;
extern char **arg_dot_from_patterns, **arg_dot_to_patterns;
extern usec_t arg_fuzz;
extern PagerFlags arg_pager_flags;
extern BusTransport arg_transport;
extern const char *arg_host;
extern LookupScope arg_scope;
extern RecursiveErrors arg_recursive_errors;
extern bool arg_man;
extern bool arg_generators;
extern char *arg_root;
extern char *arg_security_policy;
extern bool arg_offline;
extern unsigned arg_threshold;
extern unsigned arg_iterations;
extern usec_t arg_base_time;
extern char *arg_unit;
extern JsonFormatFlags arg_json_format_flags;
extern bool arg_quiet;
extern char *arg_profile;

int acquire_bus(sd_bus **bus, bool *use_full_bus);

int bus_get_unit_property_strv(sd_bus *bus, const char *path, const char *property, char ***strv);

void time_parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan);
