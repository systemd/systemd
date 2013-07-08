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
#include "dbus-socket.h"

#define BUS_SOCKET_INTERFACE                                            \
        " <interface name=\"org.freedesktop.systemd1.Socket\">\n"       \
        "  <property name=\"BindIPv6Only\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Backlog\" type=\"u\" access=\"read\"/>\n"   \
        "  <property name=\"TimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        BUS_UNIT_CGROUP_INTERFACE                                       \
        BUS_EXEC_COMMAND_INTERFACE("ExecStartPre")                      \
        BUS_EXEC_COMMAND_INTERFACE("ExecStartPost")                     \
        BUS_EXEC_COMMAND_INTERFACE("ExecStopPre")                       \
        BUS_EXEC_COMMAND_INTERFACE("ExecStopPost")                      \
        BUS_EXEC_CONTEXT_INTERFACE                                      \
        BUS_KILL_CONTEXT_INTERFACE                                      \
        BUS_CGROUP_CONTEXT_INTERFACE                                    \
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
        "  <property name=\"Transparent\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Broadcast\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"PassCredentials\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"PassSecurity\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Mark\" type=\"i\" access=\"read\"/>\n"      \
        "  <property name=\"MaxConnections\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"NAccepted\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"NConnections\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"MessageQueueMaxMessages\" type=\"x\" access=\"read\"/>\n" \
        "  <property name=\"MessageQueueMessageSize\" type=\"x\" access=\"read\"/>\n" \
        "  <property name=\"Listen\" type=\"a(ss)\" access=\"read\"/>\n"    \
        "  <property name=\"Result\" type=\"s\" access=\"read\"/>\n"    \
        "  <property name=\"ReusePort\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"SmackLabel\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SmackLabelIPIn\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SmackLabelIPOut\" type=\"s\" access=\"read\"/>\n" \
        " </interface>\n"                                               \

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SOCKET_INTERFACE                                            \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Socket\0"

const char bus_socket_interface[] _introspect_("Socket") = BUS_SOCKET_INTERFACE;

const char bus_socket_invalidating_properties[] =
        "ExecStartPre\0"
        "ExecStartPost\0"
        "ExecStopPre\0"
        "ExecStopPost\0"
        "ControlPID\0"
        "NAccepted\0"
        "NConnections\0"
        "Result\0";

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_socket_append_bind_ipv6_only, socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_socket_append_socket_result, socket_result, SocketResult);

static int bus_socket_append_listen(DBusMessageIter *i, const char *property, void *data) {

        Socket *s = SOCKET(data);
        SocketPort *p;
        DBusMessageIter array, stru;

        assert(data);
        assert(property);
        assert(s);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(ss)", &array))
                return log_oom();

        LIST_FOREACH(port, p, s->ports) {
                const char *type = socket_port_type_to_string(p);
                _cleanup_free_ char *address = NULL;
                const char *a;

                if (!dbus_message_iter_open_container(&array, DBUS_TYPE_STRUCT, NULL, &stru))
                        return log_oom();

                if (!dbus_message_iter_append_basic(&stru, DBUS_TYPE_STRING, &type))
                        return log_oom();

                switch (p->type) {
                        case SOCKET_SOCKET: {
                                int r;

                                r = socket_address_print(&p->address, &address);
                                if (r) {
                                        log_error("socket_address_print failed: %s", strerror(-r));
                                        return r;
                                }
                                a = address;
                                break;
                        }

                        case SOCKET_SPECIAL:
                        case SOCKET_MQUEUE:
                        case SOCKET_FIFO:
                                a = p->path;
                                break;

                        default:
                                a = type;
                }

                if (!dbus_message_iter_append_basic(&stru, DBUS_TYPE_STRING, &a))
                        return -ENOMEM;

                if (!dbus_message_iter_close_container(&array, &stru))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &array))
                return -ENOMEM;

        return 0;
}

static const BusProperty bus_socket_properties[] = {
        { "BindIPv6Only",   bus_socket_append_bind_ipv6_only,  "s", offsetof(Socket, bind_ipv6_only)  },
        { "Backlog",        bus_property_append_unsigned,      "u", offsetof(Socket, backlog)         },
        { "TimeoutUSec",    bus_property_append_usec,          "t", offsetof(Socket, timeout_usec)    },
        BUS_EXEC_COMMAND_PROPERTY("ExecStartPre",  offsetof(Socket, exec_command[SOCKET_EXEC_START_PRE]),  true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecStartPost", offsetof(Socket, exec_command[SOCKET_EXEC_START_POST]), true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecStopPre",   offsetof(Socket, exec_command[SOCKET_EXEC_STOP_PRE]),   true ),
        BUS_EXEC_COMMAND_PROPERTY("ExecStopPost",  offsetof(Socket, exec_command[SOCKET_EXEC_STOP_POST]),  true ),
        { "ControlPID",     bus_property_append_pid,           "u", offsetof(Socket, control_pid)     },
        { "BindToDevice",   bus_property_append_string,        "s", offsetof(Socket, bind_to_device), true },
        { "DirectoryMode",  bus_property_append_mode,          "u", offsetof(Socket, directory_mode)  },
        { "SocketMode",     bus_property_append_mode,          "u", offsetof(Socket, socket_mode)     },
        { "Accept",         bus_property_append_bool,          "b", offsetof(Socket, accept)          },
        { "KeepAlive",      bus_property_append_bool,          "b", offsetof(Socket, keep_alive)      },
        { "Priority",       bus_property_append_int,           "i", offsetof(Socket, priority)        },
        { "ReceiveBuffer",  bus_property_append_size,          "t", offsetof(Socket, receive_buffer)  },
        { "SendBuffer",     bus_property_append_size,          "t", offsetof(Socket, send_buffer)     },
        { "IPTOS",          bus_property_append_int,           "i", offsetof(Socket, ip_tos)          },
        { "IPTTL",          bus_property_append_int,           "i", offsetof(Socket, ip_ttl)          },
        { "PipeSize",       bus_property_append_size,          "t", offsetof(Socket, pipe_size)       },
        { "FreeBind",       bus_property_append_bool,          "b", offsetof(Socket, free_bind)       },
        { "Transparent",    bus_property_append_bool,          "b", offsetof(Socket, transparent)     },
        { "Broadcast",      bus_property_append_bool,          "b", offsetof(Socket, broadcast)       },
        { "PassCredentials",bus_property_append_bool,          "b", offsetof(Socket, pass_cred)       },
        { "PassSecurity",   bus_property_append_bool,          "b", offsetof(Socket, pass_sec)        },
        { "Listen",         bus_socket_append_listen,      "a(ss)", 0,                                },
        { "Mark",           bus_property_append_int,           "i", offsetof(Socket, mark)            },
        { "MaxConnections", bus_property_append_unsigned,      "u", offsetof(Socket, max_connections) },
        { "NConnections",   bus_property_append_unsigned,      "u", offsetof(Socket, n_connections)   },
        { "NAccepted",      bus_property_append_unsigned,      "u", offsetof(Socket, n_accepted)      },
        { "MessageQueueMaxMessages", bus_property_append_long, "x", offsetof(Socket, mq_maxmsg)       },
        { "MessageQueueMessageSize", bus_property_append_long, "x", offsetof(Socket, mq_msgsize)      },
        { "Result",         bus_socket_append_socket_result,   "s", offsetof(Socket, result)          },
        { "ReusePort",      bus_property_append_bool,          "b", offsetof(Socket, reuseport)       },
        { "SmackLabel",     bus_property_append_string,        "s", offsetof(Socket, smack),          true },
        { "SmackLabelIPIn", bus_property_append_string,        "s", offsetof(Socket, smack_ip_in),    true },
        { "SmackLabelIPOut",bus_property_append_string,        "s", offsetof(Socket, smack_ip_out),   true },
        {}
};

DBusHandlerResult bus_socket_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Socket *s = SOCKET(u);
        const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit",   bus_unit_properties,           u },
                { "org.freedesktop.systemd1.Socket", bus_unit_cgroup_properties,    u },
                { "org.freedesktop.systemd1.Socket", bus_socket_properties,         s },
                { "org.freedesktop.systemd1.Socket", bus_exec_context_properties,   &s->exec_context },
                { "org.freedesktop.systemd1.Socket", bus_kill_context_properties,   &s->kill_context },
                { "org.freedesktop.systemd1.Socket", bus_cgroup_context_properties, &s->cgroup_context },
                {}
        };

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
}

int bus_socket_set_property(
                Unit *u,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        Socket *s = SOCKET(u);
        int r;

        assert(name);
        assert(u);
        assert(i);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, i, mode, error);
        if (r != 0)
                return r;

        return 0;
}

int bus_socket_commit_properties(Unit *u) {
        assert(u);

        unit_realize_cgroup(u);
        return 0;
}
