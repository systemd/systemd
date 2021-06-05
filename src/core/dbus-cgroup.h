/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-bus-vtable.h"

#include "unit.h"
#include "cgroup.h"

extern const sd_bus_vtable bus_cgroup_vtable[];

int bus_property_get_tasks_max(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);

int bus_cgroup_set_property(Unit *u, CGroupContext *c, const char *name, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
