/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-bus-vtable.h"

#include "scope.h"
#include "unit.h"

extern const sd_bus_vtable bus_scope_vtable[];

int bus_scope_set_property(Unit *u, const char *name, sd_bus_message *i, UnitWriteFlags flags, sd_bus_error *error);
int bus_scope_commit_properties(Unit *u);

int bus_scope_send_request_stop(Scope *s);

int bus_scope_method_abandon(sd_bus_message *message, void *userdata, sd_bus_error *error);

int bus_scope_track_controller(Scope *s);
