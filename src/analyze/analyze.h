/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-json.h"

#include "analyze-verify-util.h"
#include "bus-util.h"
#include "pager.h"
#include "pretty-print.h"
#include "time-util.h"
#include "unit-file.h"

typedef enum DotMode {
        DEP_ALL,
        DEP_ORDER,
        DEP_REQUIRE,
} DotMode;

typedef enum CapabilityMode {
        CAPABILITY_LITERAL,
        CAPABILITY_MASK,
} CapabilityMode;

extern DotMode arg_dot;
extern CapabilityMode arg_capability;
extern char **arg_dot_from_patterns, **arg_dot_to_patterns;
extern usec_t arg_fuzz;
extern PagerFlags arg_pager_flags;
extern CatFlags arg_cat_flags;
extern BusTransport arg_transport;
extern const char *arg_host;
extern RuntimeScope arg_runtime_scope;
extern RecursiveErrors arg_recursive_errors;
extern bool arg_man;
extern bool arg_generators;
extern const char *arg_instance;
extern double arg_svg_timescale;
extern bool arg_detailed_svg;
extern char *arg_root;
extern char *arg_security_policy;
extern bool arg_offline;
extern unsigned arg_threshold;
extern unsigned arg_iterations;
extern usec_t arg_base_time;
extern char *arg_unit;
extern sd_json_format_flags_t arg_json_format_flags;
extern bool arg_quiet;
extern char *arg_profile;
extern bool arg_legend;
extern bool arg_table;
extern ImagePolicy *arg_image_policy;

int acquire_bus(sd_bus **bus, bool *use_full_bus);

int bus_get_unit_property_strv(sd_bus *bus, const char *path, const char *property, char ***strv);

void time_parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan);
