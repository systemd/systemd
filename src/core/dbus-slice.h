/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering
***/

#include "sd-bus.h"

#include "unit.h"

extern const sd_bus_vtable bus_slice_vtable[];

int bus_slice_set_property(Unit *u, const char *name, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_slice_commit_properties(Unit *u);
