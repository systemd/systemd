/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-bus.h"

#include "execute.h"

#define BUS_EXEC_STATUS_VTABLE(prefix, offset, flags)                   \
        BUS_PROPERTY_DUAL_TIMESTAMP(prefix "StartTimestamp", (offset) + offsetof(ExecStatus, start_timestamp), flags), \
        BUS_PROPERTY_DUAL_TIMESTAMP(prefix "ExitTimestamp", (offset) + offsetof(ExecStatus, exit_timestamp), flags), \
        SD_BUS_PROPERTY(prefix "PID", "u", bus_property_get_pid, (offset) + offsetof(ExecStatus, pid), flags), \
        SD_BUS_PROPERTY(prefix "Code", "i", bus_property_get_int, (offset) + offsetof(ExecStatus, code), flags), \
        SD_BUS_PROPERTY(prefix "Status", "i", bus_property_get_int, (offset) + offsetof(ExecStatus, status), flags)

#define BUS_EXEC_COMMAND_VTABLE(name, offset, flags)                    \
        SD_BUS_PROPERTY(name, "a(sasbttttuii)", bus_property_get_exec_command, offset, flags)

#define BUS_EXEC_COMMAND_LIST_VTABLE(name, offset, flags)                    \
        SD_BUS_PROPERTY(name, "a(sasbttttuii)", bus_property_get_exec_command_list, offset, flags)

extern const sd_bus_vtable bus_exec_vtable[];

int bus_property_get_exec_output(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
int bus_property_get_exec_command(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
int bus_property_get_exec_command_list(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);

int bus_exec_context_set_transient_property(Unit *u, ExecContext *c, const char *name, sd_bus_message *message, UnitSetPropertiesMode mode, sd_bus_error *error);
