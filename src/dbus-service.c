/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>

#include "dbus-unit.h"
#include "dbus-execute.h"
#include "dbus-service.h"

static const char introspection[] =
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
        "<node>"
        BUS_UNIT_INTERFACE
        BUS_PROPERTIES_INTERFACE
        " <interface name=\"org.freedesktop.systemd1.Service\">"
        "  <property name=\"Type\" type=\"s\" access=\"read\"/>"
        "  <property name=\"Restart\" type=\"s\" access=\"read\"/>"
        "  <property name=\"PIDFile\" type=\"s\" access=\"read\"/>"
        "  <property name=\"RestartUSec\" type=\"t\" access=\"read\"/>"
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>"
        BUS_EXEC_CONTEXT_INTERFACE
        "  <property name=\"PermissionsStartOnly\" type=\"b\" access=\"read\"/>"
        "  <property name=\"RootDirectoryStartOnly\" type=\"b\" access=\"read\"/>"
        "  <property name=\"ValidNoProcess\" type=\"b\" access=\"read\"/>"
        "  <property name=\"KillMode\" type=\"s\" access=\"read\"/>"
        "  <property name=\"MainPID\" type=\"u\" access=\"read\"/>"
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>"
        "  <property name=\"SysVPath\" type=\"s\" access=\"read\"/>"
        "  <property name=\"BusName\" type=\"s\" access=\"read\"/>"
        " </interface>"
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_type, service_type, ServiceType);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_restart, service_restart, ServiceRestart);

DBusHandlerResult bus_service_message_handler(Unit *u, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Service", "Type",                   bus_service_append_type,    "s", &u->service.type },
                { "org.freedesktop.systemd1.Service", "Restart",                bus_service_append_restart, "s", &u->service.restart },
                { "org.freedesktop.systemd1.Service", "PIDFile",                bus_property_append_string, "s", u->service.pid_file },
                { "org.freedesktop.systemd1.Service", "RestartUSec",            bus_property_append_usec,   "t", &u->service.restart_usec },
                { "org.freedesktop.systemd1.Service", "TimeoutUSec",            bus_property_append_usec,   "t", &u->service.timeout_usec },
                /* ExecCommand */
                BUS_EXEC_CONTEXT_PROPERTIES("org.freedesktop.systemd1.Service", u->service.exec_context),
                { "org.freedesktop.systemd1.Service", "PermissionsStartOnly",   bus_property_append_bool,   "b", &u->service.permissions_start_only },
                { "org.freedesktop.systemd1.Service", "RootDirectoryStartOnly", bus_property_append_bool,   "b", &u->service.root_directory_start_only },
                { "org.freedesktop.systemd1.Service", "ValidNoProcess",         bus_property_append_bool,   "b", &u->service.valid_no_process },
                { "org.freedesktop.systemd1.Service", "KillMode",               bus_unit_append_kill_mode,  "s", &u->service.kill_mode },
                /* MainExecStatus */
                { "org.freedesktop.systemd1.Service", "MainPID",                bus_property_append_pid,    "u", &u->service.main_pid },
                { "org.freedesktop.systemd1.Service", "ControlPID",             bus_property_append_pid,    "u", &u->service.control_pid },
                { "org.freedesktop.systemd1.Service", "SysVPath",               bus_property_append_string, "s", u->service.sysv_path },
                { "org.freedesktop.systemd1.Service", "BusName",                bus_property_append_string, "s", u->service.bus_name },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, message, introspection, properties);
}
