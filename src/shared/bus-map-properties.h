/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

typedef int (*bus_property_set_t) (sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);

struct bus_properties_map {
        const char *member;
        const char *signature;
        bus_property_set_t set;
        size_t offset;
};

enum {
        BUS_MAP_STRDUP          = 1 << 0, /* If set, each "s" message is duplicated. Thus, each pointer needs to be freed. */
        BUS_MAP_BOOLEAN_AS_BOOL = 1 << 1, /* If set, each "b" message is written to a bool pointer. If not set, "b" is written to an int pointer. */
};

int bus_map_id128(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);
int bus_map_strv_sort(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);
int bus_map_job_id(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);

int bus_message_map_all_properties(sd_bus_message *m, const struct bus_properties_map *map, unsigned flags, sd_bus_error *error, void *userdata);
int bus_map_all_properties(sd_bus *bus, const char *destination, const char *path, const struct bus_properties_map *map,
                           unsigned flags, sd_bus_error *error, sd_bus_message **reply, void *userdata);
