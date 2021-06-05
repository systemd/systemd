/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-bus-vtable.h"

#include "unit.h"

extern const sd_bus_vtable bus_socket_vtable[];

int bus_socket_set_property(Unit *u, const char *name, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_socket_commit_properties(Unit *u);
