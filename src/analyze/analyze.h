/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "bus-util.h"
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
extern PagerFlags arg_pager_flags;
extern BusTransport arg_transport;
extern const char *arg_host;
extern UnitFileScope arg_scope;
extern unsigned arg_iterations;
extern usec_t arg_base_time;
extern bool arg_quiet;

int acquire_bus(sd_bus **bus, bool *use_full_bus);

int bus_get_unit_property_strv(sd_bus *bus, const char *path, const char *property, char ***strv);

void time_parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan);
