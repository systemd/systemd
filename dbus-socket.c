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
#include "dbus-socket.h"
#include "dbus-execute.h"

static const char introspection[] =
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
        "<node>"
        BUS_UNIT_INTERFACE
        BUS_PROPERTIES_INTERFACE
        " <interface name=\"org.freedesktop.systemd1.Socket\">"
        "  <property name=\"BindIPv6Only\" type=\"b\" access=\"read\"/>"
        "  <property name=\"Backlog\" type=\"u\" access=\"read\"/>"
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>"
        BUS_EXEC_CONTEXT_INTERFACE
        "  <property name=\"KillMode\" type=\"s\" access=\"read\"/>"
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>"
        "  <property name=\"BindToDevice\" type=\"s\" access=\"read\"/>"
        "  <property name=\"DirectoryMode\" type=\"u\" access=\"read\"/>"
        "  <property name=\"SocketMode\" type=\"u\" access=\"read\"/>"
        "  <property name=\"Accept\" type=\"b\" access=\"read\"/>"
        " </interface>"
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

DBusHandlerResult bus_socket_message_handler(Unit *u, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Socket", "BindIPv6Only",  bus_property_append_bool,     "b", &u->socket.bind_ipv6_only },
                { "org.freedesktop.systemd1.Socket", "Backlog",       bus_property_append_unsigned, "u", &u->socket.backlog },
                { "org.freedesktop.systemd1.Socket", "TimeoutUSec",   bus_property_append_usec,     "t", &u->socket.timeout_usec },
                /* ExecCommand */
                BUS_EXEC_CONTEXT_PROPERTIES("org.freedesktop.systemd1.Socket", u->socket.exec_context),
                { "org.freedesktop.systemd1.Socket", "KillMode",      bus_unit_append_kill_mode,    "s", &u->socket.kill_mode },
                { "org.freedesktop.systemd1.Socket", "ControlPID",    bus_property_append_pid,      "u", &u->socket.control_pid },
                { "org.freedesktop.systemd1.Socket", "BindToDevice",  bus_property_append_string,   "s", u->socket.bind_to_device },
                { "org.freedesktop.systemd1.Socket", "DirectoryMode", bus_property_append_mode,     "u", &u->socket.directory_mode },
                { "org.freedesktop.systemd1.Socket", "SocketMode",    bus_property_append_mode,     "u", &u->socket.socket_mode },
                { "org.freedesktop.systemd1.Socket", "Accept",        bus_property_append_bool,     "b", &u->socket.accept },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, message, introspection, properties);
}
