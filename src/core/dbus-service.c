/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>

#include "dbus-unit.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-service.h"
#include "dbus-common.h"
#include "selinux-access.h"

#define BUS_SERVICE_INTERFACE                                           \
        " <interface name=\"org.freedesktop.systemd1.Service\">\n"      \
        "  <property name=\"Type\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Restart\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"PIDFile\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"NotifyAccess\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"RestartUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"WatchdogUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"WatchdogTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"WatchdogTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"StartLimitInterval\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"StartLimitBurst\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"StartLimitAction\" type=\"s\" access=\"readwrite\"/>\n" \
        BUS_EXEC_COMMAND_INTERFACE("ExecStartPre")                      \
        BUS_EXEC_COMMAND_INTERFACE("ExecStart")                         \
        BUS_EXEC_COMMAND_INTERFACE("ExecStartPost")                     \
        BUS_EXEC_COMMAND_INTERFACE("ExecReload")                        \
        BUS_EXEC_COMMAND_INTERFACE("ExecStop")                          \
        BUS_EXEC_COMMAND_INTERFACE("ExecStopPost")                      \
        BUS_EXEC_CONTEXT_INTERFACE                                      \
        BUS_KILL_CONTEXT_INTERFACE                                      \
        BUS_UNIT_CGROUP_INTERFACE                                       \
        "  <property name=\"PermissionsStartOnly\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"RootDirectoryStartOnly\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"RemainAfterExit\" type=\"b\" access=\"read\"/>\n" \
        BUS_EXEC_STATUS_INTERFACE("ExecMain")                           \
        "  <property name=\"MainPID\" type=\"u\" access=\"read\"/>\n"   \
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"BusName\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"StatusText\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Result\" type=\"s\" access=\"read\"/>\n"    \
       " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SERVICE_INTERFACE                                           \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Service\0"

const char bus_service_interface[] _introspect_("Service") = BUS_SERVICE_INTERFACE;

const char bus_service_invalidating_properties[] =
        "ExecStartPre\0"
        "ExecStart\0"
        "ExecStartPost\0"
        "ExecReload\0"
        "ExecStop\0"
        "ExecStopPost\0"
        "ExecMain\0"
        "WatchdogTimestamp\0"
        "WatchdogTimestampMonotonic\0"
        "MainPID\0"
        "ControlPID\0"
        "StatusText\0"
        "Result\0";

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_type, service_type, ServiceType);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_restart, service_restart, ServiceRestart);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_notify_access, notify_access, NotifyAccess);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_service_result, service_result, ServiceResult);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_service_append_start_limit_action, start_limit_action, StartLimitAction);
static DEFINE_BUS_PROPERTY_SET_ENUM(bus_service_set_start_limit_action, start_limit_action, StartLimitAction);

static const BusProperty bus_exec_main_status_properties[] = {
        { "ExecMainStartTimestamp",         bus_property_append_usec, "t", offsetof(ExecStatus, start_timestamp.realtime)  },
        { "ExecMainStartTimestampMonotonic",bus_property_append_usec, "t", offsetof(ExecStatus, start_timestamp.monotonic) },
        { "ExecMainExitTimestamp",          bus_property_append_usec, "t", offsetof(ExecStatus, start_timestamp.realtime)  },
        { "ExecMainExitTimestampMonotonic", bus_property_append_usec, "t", offsetof(ExecStatus, start_timestamp.monotonic) },
        { "ExecMainPID",                    bus_property_append_pid,  "u", offsetof(ExecStatus, pid)                       },
        { "ExecMainCode",                   bus_property_append_int,  "i", offsetof(ExecStatus, code)                      },
        { "ExecMainStatus",                 bus_property_append_int,  "i", offsetof(ExecStatus, status)                    },
        { NULL, }
};

static const BusProperty bus_service_properties[] = {
        { "Type",                   bus_service_append_type,          "s", offsetof(Service, type)                         },
        { "Restart",                bus_service_append_restart,       "s", offsetof(Service, restart)                      },
        { "PIDFile",                bus_property_append_string,       "s", offsetof(Service, pid_file),               true },
        { "NotifyAccess",           bus_service_append_notify_access, "s", offsetof(Service, notify_access)                },
        { "RestartUSec",            bus_property_append_usec,         "t", offsetof(Service, restart_usec)                 },
        { "TimeoutUSec",            bus_property_append_usec,         "t", offsetof(Service, timeout_start_usec)           },
        { "TimeoutStartUSec",       bus_property_append_usec,         "t", offsetof(Service, timeout_start_usec)           },
        { "TimeoutStopUSec",        bus_property_append_usec,         "t", offsetof(Service, timeout_stop_usec)            },
        { "WatchdogUSec",           bus_property_append_usec,         "t", offsetof(Service, watchdog_usec)                },
        { "WatchdogTimestamp",      bus_property_append_usec,         "t", offsetof(Service, watchdog_timestamp.realtime)  },
        { "WatchdogTimestampMonotonic",bus_property_append_usec,      "t", offsetof(Service, watchdog_timestamp.monotonic) },
        { "StartLimitInterval",     bus_property_append_usec,         "t", offsetof(Service, start_limit.interval)         },
        { "StartLimitBurst",        bus_property_append_uint32,       "u", offsetof(Service, start_limit.burst)            },
        { "StartLimitAction",       bus_service_append_start_limit_action,"s", offsetof(Service, start_limit_action), false, bus_service_set_start_limit_action},
        BUS_EXEC_COMMAND_PROPERTY("ExecStartPre",  offsetof(Service, exec_command[SERVICE_EXEC_START_PRE]),  true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecStart",     offsetof(Service, exec_command[SERVICE_EXEC_START]),      true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecStartPost", offsetof(Service, exec_command[SERVICE_EXEC_START_POST]), true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecReload",    offsetof(Service, exec_command[SERVICE_EXEC_RELOAD]),     true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecStop",      offsetof(Service, exec_command[SERVICE_EXEC_STOP]),       true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecStopPost",  offsetof(Service, exec_command[SERVICE_EXEC_STOP_POST]),  true ),
        { "PermissionsStartOnly",   bus_property_append_bool,         "b", offsetof(Service, permissions_start_only)       },
        { "RootDirectoryStartOnly", bus_property_append_bool,         "b", offsetof(Service, root_directory_start_only)    },
        { "RemainAfterExit",        bus_property_append_bool,         "b", offsetof(Service, remain_after_exit)            },
        { "GuessMainPID",           bus_property_append_bool,         "b", offsetof(Service, guess_main_pid)               },
        { "MainPID",                bus_property_append_pid,          "u", offsetof(Service, main_pid)                     },
        { "ControlPID",             bus_property_append_pid,          "u", offsetof(Service, control_pid)                  },
        { "BusName",                bus_property_append_string,       "s", offsetof(Service, bus_name),               true },
        { "StatusText",             bus_property_append_string,       "s", offsetof(Service, status_text),            true },
        { "Result",                 bus_service_append_service_result,"s", offsetof(Service, result)                       },
        { NULL, }
};

DBusHandlerResult bus_service_message_handler(Unit *u, DBusConnection *connection, DBusMessage *message) {
        Service *s = SERVICE(u);

        const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit",    bus_unit_properties,             u },
                { "org.freedesktop.systemd1.Service", bus_service_properties,          s },
                { "org.freedesktop.systemd1.Service", bus_exec_context_properties,     &s->exec_context },
                { "org.freedesktop.systemd1.Service", bus_kill_context_properties,     &s->kill_context },
                { "org.freedesktop.systemd1.Service", bus_exec_main_status_properties, &s->main_exec_status },
                { "org.freedesktop.systemd1.Service", bus_unit_cgroup_properties,      u },
                { NULL, }
        };

        SELINUX_UNIT_ACCESS_CHECK(u, connection, message, "status");

        return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, bps);
}
