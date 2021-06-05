/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-bus-vtable.h"

#include "kill.h"
#include "unit.h"

extern const sd_bus_vtable bus_kill_vtable[];

int bus_kill_context_set_transient_property(Unit *u, KillContext *c, const char *name, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
