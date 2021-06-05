/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "bus-map-properties.h"
#include "time-util.h"

int list_machines(int argc, char *argv[], void *userdata);

struct machine_info {
        bool is_host;
        char *name;
        char *state;
        char *control_group;
        uint32_t n_failed_units;
        uint32_t n_jobs;
        usec_t timestamp;
};

void machine_info_clear(struct machine_info *info);

extern const struct bus_properties_map machine_info_property_map[];
