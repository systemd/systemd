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

#include "unit.h"
#include "socket.h"
#include "dbus-unit.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-cgroup.h"
#include "dbus-socket.h"
#include "bus-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, socket_result, SocketResult);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_bind_ipv6_only, socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);

static int property_get_listen(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                sd_bus_error *error,
                void *userdata) {


        Socket *s = SOCKET(userdata);
        SocketPort *p;
        int r;

        assert(bus);
        assert(reply);
        assert(s);

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        LIST_FOREACH(port, p, s->ports) {
                _cleanup_free_ char *address = NULL;
                const char *a;

                switch (p->type) {
                        case SOCKET_SOCKET: {
                                r = socket_address_print(&p->address, &address);
                                if (r)
                                        return r;

                                a = address;
                                break;
                        }

                        case SOCKET_SPECIAL:
                        case SOCKET_MQUEUE:
                        case SOCKET_FIFO:
                                a = p->path;
                                break;

                        default:
                                assert_not_reached("Unknown socket type");
                }

                r = sd_bus_message_append(reply, "(ss)", socket_port_type_to_string(p), a);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

const sd_bus_vtable bus_socket_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("BindIPv6Only", "s", property_get_bind_ipv6_only, offsetof(Socket, bind_ipv6_only), 0),
        SD_BUS_PROPERTY("Backlog", "u", bus_property_get_unsigned, offsetof(Socket, backlog), 0),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(Socket, timeout_usec), 0),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Socket, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BindToDevice", "s", NULL, offsetof(Socket, bind_to_device), 0),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Socket, directory_mode), 0),
        SD_BUS_PROPERTY("SocketMode", "u", bus_property_get_mode, offsetof(Socket, socket_mode), 0),
        SD_BUS_PROPERTY("Accept", "b", bus_property_get_bool, offsetof(Socket, accept), 0),
        SD_BUS_PROPERTY("KeepAlive", "b", bus_property_get_bool, offsetof(Socket, keep_alive), 0),
        SD_BUS_PROPERTY("Priority", "i", bus_property_get_int, offsetof(Socket, priority), 0),
        SD_BUS_PROPERTY("ReceiveBuffer", "t", bus_property_get_size, offsetof(Socket, receive_buffer), 0),
        SD_BUS_PROPERTY("SendBuffer", "t", bus_property_get_size, offsetof(Socket, send_buffer), 0),
        SD_BUS_PROPERTY("IPTOS", "i", bus_property_get_int, offsetof(Socket, ip_tos), 0),
        SD_BUS_PROPERTY("IPTTL", "i", bus_property_get_int, offsetof(Socket, ip_ttl), 0),
        SD_BUS_PROPERTY("PipeSize", "t", bus_property_get_size, offsetof(Socket, pipe_size), 0),
        SD_BUS_PROPERTY("FreeBind", "b", bus_property_get_bool, offsetof(Socket, free_bind), 0),
        SD_BUS_PROPERTY("Transparent", "b", bus_property_get_bool, offsetof(Socket, transparent), 0),
        SD_BUS_PROPERTY("Broadcast", "b", bus_property_get_bool, offsetof(Socket, broadcast), 0),
        SD_BUS_PROPERTY("PassCredentials", "b", bus_property_get_bool, offsetof(Socket, pass_cred), 0),
        SD_BUS_PROPERTY("PassSecurity", "b", bus_property_get_bool, offsetof(Socket, pass_sec), 0),
        SD_BUS_PROPERTY("Listen", "a(ss)", property_get_listen, 0, 0),
        SD_BUS_PROPERTY("Mark", "i", bus_property_get_int, offsetof(Socket, mark), 0),
        SD_BUS_PROPERTY("MaxConnections", "u", bus_property_get_unsigned, offsetof(Socket, max_connections), 0),
        SD_BUS_PROPERTY("NConnections", "u", bus_property_get_unsigned, offsetof(Socket, n_connections), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NAccepted", "u", bus_property_get_unsigned, offsetof(Socket, n_accepted), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("MessageQueueMaxMessages", "x", bus_property_get_long, offsetof(Socket, mq_maxmsg), 0),
        SD_BUS_PROPERTY("MessageQueueMessageSize", "x", bus_property_get_long, offsetof(Socket, mq_msgsize), 0),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Socket, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ReusePort", "b",  bus_property_get_bool, offsetof(Socket, reuse_port), 0),
        SD_BUS_PROPERTY("SmackLabel", "s", NULL, offsetof(Socket, smack), 0),
        SD_BUS_PROPERTY("SmackLabelIPIn", "s", NULL, offsetof(Socket, smack_ip_in), 0),
        SD_BUS_PROPERTY("SmackLabelIPOut", "s", NULL, offsetof(Socket, smack_ip_out), 0),
        BUS_EXEC_COMMAND_VTABLE("ExecStartPre", offsetof(Socket, exec_command[SOCKET_EXEC_START_PRE]), 0),
        BUS_EXEC_COMMAND_VTABLE("ExecStartPost", offsetof(Socket, exec_command[SOCKET_EXEC_START_POST]), 0),
        BUS_EXEC_COMMAND_VTABLE("ExecStopPre", offsetof(Socket, exec_command[SOCKET_EXEC_STOP_PRE]), 0),
        BUS_EXEC_COMMAND_VTABLE("ExecStopPost", offsetof(Socket, exec_command[SOCKET_EXEC_STOP_POST]), 0),
        SD_BUS_VTABLE_END
};

const char* const bus_socket_changing_properties[] = {
        "ControlPID",
        "NAccepted",
        "NConnections",
        "Result",
        NULL
};

int bus_socket_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        Socket *s = SOCKET(u);

        assert(s);
        assert(name);
        assert(message);

        return bus_cgroup_set_property(u, &s->cgroup_context, name, message, mode, error);
}

int bus_socket_commit_properties(Unit *u) {
        assert(u);

        unit_realize_cgroup(u);
        return 0;
}
