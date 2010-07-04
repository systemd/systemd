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

#define BUS_SERVICE_INTERFACE                                           \
        " <interface name=\"org.freedesktop.systemd1.Service\">\n"      \
        "  <property name=\"Type\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Restart\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"PIDFile\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"NotifyAccess\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"RestartUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        BUS_EXEC_CONTEXT_INTERFACE                                      \
        "  <property name=\"PermissionsStartOnly\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"RootDirectoryStartOnly\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"ValidNoProcess\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"KillMode\" type=\"s\" access=\"read\"/>\n"  \
        BUS_EXEC_STATUS_INTERFACE("ExecMain")                           \
        "  <property name=\"MainPID\" type=\"u\" access=\"read\"/>\n"   \
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"SysVStartPriority\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"SysVRunLevels\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SysVPath\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"BusName\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"StatusText\" type=\"s\" access=\"read\"/>\n" \
       " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SERVICE_INTERFACE                                           \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

const char bus_service_interface[] = BUS_SERVICE_INTERFACE;

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_type, service_type, ServiceType);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_restart, service_restart, ServiceRestart);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_notify_access, notify_access, NotifyAccess);

DBusHandlerResult bus_service_message_handler(Unit *u, DBusConnection *connection, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Service", "Type",                   bus_service_append_type,    "s", &u->service.type                      },
                { "org.freedesktop.systemd1.Service", "Restart",                bus_service_append_restart, "s", &u->service.restart                   },
                { "org.freedesktop.systemd1.Service", "PIDFile",                bus_property_append_string, "s", u->service.pid_file                   },
                { "org.freedesktop.systemd1.Service", "NotifyAccess",           bus_service_append_notify_access, "s", &u->service.notify_access       },
                { "org.freedesktop.systemd1.Service", "RestartUSec",            bus_property_append_usec,   "t", &u->service.restart_usec              },
                { "org.freedesktop.systemd1.Service", "TimeoutUSec",            bus_property_append_usec,   "t", &u->service.timeout_usec              },
                /* ExecCommand */
                BUS_EXEC_CONTEXT_PROPERTIES("org.freedesktop.systemd1.Service", u->service.exec_context),
                { "org.freedesktop.systemd1.Service", "PermissionsStartOnly",   bus_property_append_bool,   "b", &u->service.permissions_start_only    },
                { "org.freedesktop.systemd1.Service", "RootDirectoryStartOnly", bus_property_append_bool,   "b", &u->service.root_directory_start_only },
                { "org.freedesktop.systemd1.Service", "ValidNoProcess",         bus_property_append_bool,   "b", &u->service.valid_no_process          },
                { "org.freedesktop.systemd1.Service", "KillMode",               bus_unit_append_kill_mode,  "s", &u->service.kill_mode                 },
                BUS_EXEC_STATUS_PROPERTIES("org.freedesktop.systemd1.Service", u->service.main_exec_status, "ExecMain"),
                { "org.freedesktop.systemd1.Service", "MainPID",                bus_property_append_pid,    "u", &u->service.main_pid                  },
                { "org.freedesktop.systemd1.Service", "ControlPID",             bus_property_append_pid,    "u", &u->service.control_pid               },
                { "org.freedesktop.systemd1.Service", "SysVPath",               bus_property_append_string, "s", u->service.sysv_path                  },
                { "org.freedesktop.systemd1.Service", "BusName",                bus_property_append_string, "s", u->service.bus_name                   },
                { "org.freedesktop.systemd1.Service", "StatusText",             bus_property_append_string, "s", u->service.status_text                },
                { "org.freedesktop.systemd1.Service", "SysVRunLevels",          bus_property_append_string, "s", u->service.sysv_runlevels             },
                { "org.freedesktop.systemd1.Service", "SysVStartPriority",      bus_property_append_int,    "i", &u->service.sysv_start_priority       },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, connection, message, INTROSPECTION, properties);
}
