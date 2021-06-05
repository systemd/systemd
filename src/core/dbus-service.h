/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-bus-vtable.h"

#include "unit.h"

extern const sd_bus_vtable bus_service_vtable[];

int bus_service_set_property(Unit *u, const char *name, sd_bus_message *i, UnitWriteFlags flags, sd_bus_error *error);
int bus_service_method_bind_mount(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_service_method_mount_image(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_service_commit_properties(Unit *u);
