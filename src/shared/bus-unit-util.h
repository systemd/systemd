/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "install.h"
#include "unit-def.h"

typedef struct UnitInfo {
        const char *machine;
        const char *id;
        const char *description;
        const char *load_state;
        const char *active_state;
        const char *sub_state;
        const char *following;
        const char *unit_path;
        uint32_t job_id;
        const char *job_type;
        const char *job_path;
} UnitInfo;

int bus_parse_unit_info(sd_bus_message *message, UnitInfo *u);

int bus_append_unit_property_assignment(sd_bus_message *m, UnitType t, const char *assignment);
int bus_append_unit_property_assignment_many(sd_bus_message *m, UnitType t, char **l);

int bus_deserialize_and_dump_unit_file_changes(sd_bus_message *m, bool quiet, UnitFileChange **changes, size_t *n_changes);

int unit_load_state(sd_bus *bus, const char *name, char **load_state);
