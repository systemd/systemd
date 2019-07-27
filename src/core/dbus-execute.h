/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "sd-bus-vtable.h"

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

#define BUS_EXEC_EX_COMMAND_LIST_VTABLE(name, offset, flags)                    \
        SD_BUS_PROPERTY(name, "a(sasasttttuii)", bus_property_get_exec_ex_command_list, offset, flags)

extern const sd_bus_vtable bus_exec_vtable[];

int bus_property_get_exec_output(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
int bus_property_get_exec_command(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
int bus_property_get_exec_command_list(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
int bus_property_get_exec_ex_command_list(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);

int bus_exec_context_set_transient_property(Unit *u, ExecContext *c, const char *name, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_set_transient_exec_command(Unit *u, const char *name, ExecCommand **exec_command, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
