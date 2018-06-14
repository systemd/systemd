/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "install.h"
#include "output-mode.h"
#include "sd-bus.h"
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

typedef struct BusWaitForJobs BusWaitForJobs;

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret);
void bus_wait_for_jobs_free(BusWaitForJobs *d);
int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path);
int bus_wait_for_jobs(BusWaitForJobs *d, bool quiet, const char* const* extra_args);
int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet);

DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForJobs*, bus_wait_for_jobs_free);

int bus_deserialize_and_dump_unit_file_changes(sd_bus_message *m, bool quiet, UnitFileChange **changes, size_t *n_changes);

int unit_show_processes(sd_bus *bus, const char *unit, const char *cgroup_path, const char *prefix, unsigned n_columns, OutputFlags flags, sd_bus_error *error);

int unit_load_state(sd_bus *bus, const char *name, char **load_state);
