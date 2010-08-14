/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include "dbus-socket.h"
#include "dbus-execute.h"

#define BUS_SOCKET_INTERFACE                                            \
        " <interface name=\"org.freedesktop.systemd1.Socket\">\n"       \
        "  <property name=\"BindIPv6Only\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Backlog\" type=\"u\" access=\"read\"/>\n"   \
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        BUS_EXEC_COMMAND_INTERFACE("ExecStartPre")                      \
        BUS_EXEC_COMMAND_INTERFACE("ExecStartPost")                     \
        BUS_EXEC_COMMAND_INTERFACE("ExecStopPre")                       \
        BUS_EXEC_COMMAND_INTERFACE("ExecStopPost")                      \
        BUS_EXEC_CONTEXT_INTERFACE                                      \
        "  <property name=\"ControlPID\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"BindToDevice\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"DirectoryMode\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"SocketMode\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"Accept\" type=\"b\" access=\"read\"/>\n"    \
        "  <property name=\"KeepAlive\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Priority\" type=\"i\" access=\"read\"/>\n"  \
        "  <property name=\"ReceiveBuffer\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"SendBuffer\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"IPTOS\" type=\"i\" access=\"read\"/>\n"     \
        "  <property name=\"IPTTL\" type=\"i\" access=\"read\"/>\n"     \
        "  <property name=\"PipeSize\" type=\"t\" access=\"read\"/>\n"  \
        "  <property name=\"FreeBind\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"Mark\" type=\"i\" access=\"read\"/>\n"      \
        "  <property name=\"MaxConnections\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"NAccepted\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"NConnections\" type=\"u\" access=\"read\"/>\n" \
        " </interface>\n"                                               \

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SOCKET_INTERFACE                                            \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

const char bus_socket_interface[] = BUS_SOCKET_INTERFACE;

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_socket_append_bind_ipv6_only, socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);

DBusHandlerResult bus_socket_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Socket", "BindIPv6Only",   bus_socket_append_bind_ipv6_only, "s", &u->socket.bind_ipv6_only  },
                { "org.freedesktop.systemd1.Socket", "Backlog",        bus_property_append_unsigned,     "u", &u->socket.backlog         },
                { "org.freedesktop.systemd1.Socket", "TimeoutUSec",    bus_property_append_usec,         "t", &u->socket.timeout_usec    },
                BUS_EXEC_COMMAND_PROPERTY("org.freedesktop.systemd1.Socket", u->service.exec_command[SOCKET_EXEC_START_PRE],  "ExecStartPre"),
                BUS_EXEC_COMMAND_PROPERTY("org.freedesktop.systemd1.Socket", u->service.exec_command[SOCKET_EXEC_START_POST], "ExecStartPost"),
                BUS_EXEC_COMMAND_PROPERTY("org.freedesktop.systemd1.Socket", u->service.exec_command[SOCKET_EXEC_STOP_PRE],   "ExecStopPre"),
                BUS_EXEC_COMMAND_PROPERTY("org.freedesktop.systemd1.Socket", u->service.exec_command[SOCKET_EXEC_STOP_POST],  "ExecStopPost"),
                BUS_EXEC_CONTEXT_PROPERTIES("org.freedesktop.systemd1.Socket", u->socket.exec_context),
                { "org.freedesktop.systemd1.Socket", "ControlPID",     bus_property_append_pid,          "u", &u->socket.control_pid     },
                { "org.freedesktop.systemd1.Socket", "BindToDevice",   bus_property_append_string,       "s", u->socket.bind_to_device   },
                { "org.freedesktop.systemd1.Socket", "DirectoryMode",  bus_property_append_mode,         "u", &u->socket.directory_mode  },
                { "org.freedesktop.systemd1.Socket", "SocketMode",     bus_property_append_mode,         "u", &u->socket.socket_mode     },
                { "org.freedesktop.systemd1.Socket", "Accept",         bus_property_append_bool,         "b", &u->socket.accept          },
                { "org.freedesktop.systemd1.Socket", "KeepAlive",      bus_property_append_bool,         "b", &u->socket.keep_alive      },
                { "org.freedesktop.systemd1.Socket", "Priority",       bus_property_append_int,          "i", &u->socket.priority        },
                { "org.freedesktop.systemd1.Socket", "ReceiveBuffer",  bus_property_append_size,         "t", &u->socket.receive_buffer  },
                { "org.freedesktop.systemd1.Socket", "SendBuffer",     bus_property_append_size,         "t", &u->socket.send_buffer     },
                { "org.freedesktop.systemd1.Socket", "IPTOS",          bus_property_append_int,          "i", &u->socket.ip_tos          },
                { "org.freedesktop.systemd1.Socket", "IPTTL",          bus_property_append_int,          "i", &u->socket.ip_ttl          },
                { "org.freedesktop.systemd1.Socket", "PipeSize",       bus_property_append_size,         "t", &u->socket.pipe_size       },
                { "org.freedesktop.systemd1.Socket", "FreeBind",       bus_property_append_bool,         "b", &u->socket.free_bind       },
                { "org.freedesktop.systemd1.Socket", "Mark",           bus_property_append_int,          "i", &u->socket.mark            },
                { "org.freedesktop.systemd1.Socket", "MaxConnections", bus_property_append_unsigned,     "u", &u->socket.max_connections },
                { "org.freedesktop.systemd1.Socket", "NConnections",   bus_property_append_unsigned,     "u", &u->socket.n_connections   },
                { "org.freedesktop.systemd1.Socket", "NAccepted",      bus_property_append_unsigned,     "u", &u->socket.n_accepted      },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, c, message, INTROSPECTION, properties);
}
