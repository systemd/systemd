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
#include "dbus-cgroup.h"
#include "dbus-common.h"
#include "selinux-access.h"
#include "dbus-mount.h"

#define BUS_MOUNT_INTERFACE                                             \
        " <interface name=\"org.freedesktop.systemd1.Mount\">\n"        \
        "  <property name=\"Where\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"What\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Options\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"Type\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        BUS_UNIT_CGROUP_INTERFACE                                       \
        BUS_EXEC_COMMAND_INTERFACE("ExecMount")                         \
        BUS_EXEC_COMMAND_INTERFACE("ExecUnmount")                       \
        BUS_EXEC_COMMAND_INTERFACE("ExecRemount")                       \
        BUS_EXEC_CONTEXT_INTERFACE                                      \
        BUS_KILL_CONTEXT_INTERFACE                                      \
        BUS_CGROUP_CONTEXT_INTERFACE                                    \
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"DirectoryMode\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"Result\" type=\"s\" access=\"read\"/>\n"    \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_MOUNT_INTERFACE                                             \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Mount\0"

const char bus_mount_interface[] _introspect_("Mount") = BUS_MOUNT_INTERFACE;

const char bus_mount_invalidating_properties[] =
        "What\0"
        "Options\0"
        "Type\0"
        "ExecMount\0"
        "ExecUnmount\0"
        "ExecRemount\0"
        "ControlPID\0"
        "Result\0";

static int bus_mount_append_what(DBusMessageIter *i, const char *property, void *data) {
        Mount *m = data;
        const char *d;

        assert(i);
        assert(property);
        assert(m);

        if (m->from_proc_self_mountinfo && m->parameters_proc_self_mountinfo.what)
                d = m->parameters_proc_self_mountinfo.what;
        else if (m->from_fragment && m->parameters_fragment.what)
                d = m->parameters_fragment.what;
        else
                d = "";

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static int bus_mount_append_options(DBusMessageIter *i, const char *property, void *data) {
        Mount *m = data;
        const char *d;

        assert(i);
        assert(property);
        assert(m);

        if (m->from_proc_self_mountinfo && m->parameters_proc_self_mountinfo.options)
                d = m->parameters_proc_self_mountinfo.options;
        else if (m->from_fragment && m->parameters_fragment.options)
                d = m->parameters_fragment.options;
        else
                d = "";

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static int bus_mount_append_type(DBusMessageIter *i, const char *property, void *data) {
        Mount *m = data;
        const char *d;

        assert(i);
        assert(property);
        assert(m);

        if (m->from_proc_self_mountinfo && m->parameters_proc_self_mountinfo.fstype)
                d = m->parameters_proc_self_mountinfo.fstype;
        else if (m->from_fragment && m->parameters_fragment.fstype)
                d = m->parameters_fragment.fstype;
        else
                d = "";

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_mount_append_mount_result, mount_result, MountResult);

static const BusProperty bus_mount_properties[] = {
        { "Where",         bus_property_append_string, "s", offsetof(Mount, where),    true },
        { "What",          bus_mount_append_what,      "s", 0 },
        { "Options",       bus_mount_append_options,   "s", 0 },
        { "Type",          bus_mount_append_type,      "s", 0 },
        { "TimeoutUSec",   bus_property_append_usec,   "t", offsetof(Mount, timeout_usec)   },
        BUS_EXEC_COMMAND_PROPERTY("ExecMount",   offsetof(Mount, exec_command[MOUNT_EXEC_MOUNT]),   false),
        BUS_EXEC_COMMAND_PROPERTY("ExecUnmount", offsetof(Mount, exec_command[MOUNT_EXEC_UNMOUNT]), false),
        BUS_EXEC_COMMAND_PROPERTY("ExecRemount", offsetof(Mount, exec_command[MOUNT_EXEC_REMOUNT]), false),
        { "ControlPID",    bus_property_append_pid,    "u", offsetof(Mount, control_pid)    },
        { "DirectoryMode", bus_property_append_mode,   "u", offsetof(Mount, directory_mode) },
        { "Result",        bus_mount_append_mount_result, "s", offsetof(Mount, result)      },
        { NULL, }
};

DBusHandlerResult bus_mount_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Mount *m = MOUNT(u);

        const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit",  bus_unit_properties,           u },
                { "org.freedesktop.systemd1.Mount", bus_unit_cgroup_properties,    u },
                { "org.freedesktop.systemd1.Mount", bus_mount_properties,          m },
                { "org.freedesktop.systemd1.Mount", bus_exec_context_properties,   &m->exec_context },
                { "org.freedesktop.systemd1.Mount", bus_kill_context_properties,   &m->kill_context },
                { "org.freedesktop.systemd1.Mount", bus_cgroup_context_properties, &m->cgroup_context },
                { NULL, }
        };

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps );
}

int bus_mount_set_property(
                Unit *u,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        Mount *m = MOUNT(u);
        int r;

        assert(name);
        assert(u);
        assert(i);

        r = bus_cgroup_set_property(u, &m->cgroup_context, name, i, mode, error);
        if (r != 0)
                return r;

        return 0;
}

int bus_mount_commit_properties(Unit *u) {
        assert(u);

        unit_realize_cgroup(u);
        return 0;
}
