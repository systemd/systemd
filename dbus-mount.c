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

#include "dbus-unit.h"
#include "dbus-mount.h"
#include "dbus-execute.h"

static const char introspection[] =
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
        "<node>"
        BUS_UNIT_INTERFACE
        BUS_PROPERTIES_INTERFACE
        " <interface name=\"org.freedesktop.systemd1.Mount\">"
        "  <property name=\"Where\" type=\"s\" access=\"read\"/>"
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>"
        BUS_EXEC_CONTEXT_INTERFACE
        "  <property name=\"KillMode\" type=\"s\" access=\"read\"/>"
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>"
        " </interface>"
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

DBusHandlerResult bus_mount_message_handler(Unit *u, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Mount", "Where",       bus_property_append_string, "s", u->mount.where         },
                /* Where, Options, fstype */
                { "org.freedesktop.systemd1.Mount", "TimeoutUSec", bus_property_append_usec,   "t", &u->mount.timeout_usec },
                /* ExecCommand */
                BUS_EXEC_CONTEXT_PROPERTIES("org.freedesktop.systemd1.Mount", u->mount.exec_context),
                { "org.freedesktop.systemd1.Mount", "KillMode",    bus_unit_append_kill_mode,  "s", &u->mount.kill_mode    },
                { "org.freedesktop.systemd1.Mount", "ControlPID",  bus_property_append_pid,    "u", &u->mount.control_pid  },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, message, introspection, properties);
}
