/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2010 Maarten Lankhorst

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
#include "dbus-swap.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-common.h"
#include "selinux-access.h"

#define BUS_SWAP_INTERFACE                                              \
        " <interface name=\"org.freedesktop.systemd1.Swap\">\n"         \
        "  <property name=\"What\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Priority\" type=\"i\" access=\"read\"/>\n"  \
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        BUS_EXEC_COMMAND_INTERFACE("ExecActivate")                      \
        BUS_EXEC_COMMAND_INTERFACE("ExecDeactivate")                    \
        BUS_EXEC_CONTEXT_INTERFACE                                      \
        BUS_KILL_CONTEXT_INTERFACE                                      \
        BUS_UNIT_CGROUP_INTERFACE                                       \
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"Result\" type=\"s\" access=\"read\"/>\n"    \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SWAP_INTERFACE                                              \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Swap\0"

const char bus_swap_interface[] _introspect_("Swap") = BUS_SWAP_INTERFACE;

const char bus_swap_invalidating_properties[] =
        "What\0"
        "Priority\0"
        "ExecActivate\0"
        "ExecDeactivate\0"
        "ControlPID\0"
        "Result\0";

static int bus_swap_append_priority(DBusMessageIter *i, const char *property, void *data) {
        Swap *s = data;
        dbus_int32_t j;

        assert(i);
        assert(property);
        assert(s);

        if (s->from_proc_swaps)
                j = s->parameters_proc_swaps.priority;
        else if (s->from_fragment)
                j = s->parameters_fragment.priority;
        else
                j = -1;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_INT32, &j))
                return -ENOMEM;

        return 0;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_swap_append_swap_result, swap_result, SwapResult);

static const BusProperty bus_swap_properties[] = {
        { "What",       bus_property_append_string, "s", offsetof(Swap, what),  true },
        { "Priority",   bus_swap_append_priority,   "i", 0 },
        BUS_EXEC_COMMAND_PROPERTY("ExecActivate",   offsetof(Swap, exec_command[SWAP_EXEC_ACTIVATE]),   false),
        BUS_EXEC_COMMAND_PROPERTY("ExecDeactivate", offsetof(Swap, exec_command[SWAP_EXEC_DEACTIVATE]), false),
        { "ControlPID", bus_property_append_pid,    "u", offsetof(Swap, control_pid) },
        { "Result",     bus_swap_append_swap_result,"s", offsetof(Swap, result)      },
        { NULL, }
};

DBusHandlerResult bus_swap_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Swap *s = SWAP(u);
        const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit", bus_unit_properties,         u },
                { "org.freedesktop.systemd1.Swap", bus_swap_properties,         s },
                { "org.freedesktop.systemd1.Swap", bus_exec_context_properties, &s->exec_context },
                { "org.freedesktop.systemd1.Swap", bus_kill_context_properties, &s->kill_context },
                { "org.freedesktop.systemd1.Swap", bus_unit_cgroup_properties,  u },
                { NULL, }
        };

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
}
