/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include "alloc-util.h"
#include "bus-util.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-socket.h"
#include "fd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket.h"
#include "socket-util.h"
#include "string-util.h"
#include "unit.h"
#include "user-util.h"
#include "utf8.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, socket_result, SocketResult);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_bind_ipv6_only, socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);

static int property_get_listen(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


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
                        case SOCKET_USB_FUNCTION:
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


static int property_get_fdname(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Socket *s = SOCKET(userdata);

        assert(bus);
        assert(reply);
        assert(s);

        return sd_bus_message_append(reply, "s", socket_fdname(s));
}

const sd_bus_vtable bus_socket_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("BindIPv6Only", "s", property_get_bind_ipv6_only, offsetof(Socket, bind_ipv6_only), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Backlog", "u", bus_property_get_unsigned, offsetof(Socket, backlog), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(Socket, timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("BindToDevice", "s", NULL, offsetof(Socket, bind_to_device), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SocketUser", "s", NULL, offsetof(Socket, user), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SocketGroup", "s", NULL, offsetof(Socket, group), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SocketMode", "u", bus_property_get_mode, offsetof(Socket, socket_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Socket, directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Accept", "b", bus_property_get_bool, offsetof(Socket, accept), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Writable", "b", bus_property_get_bool, offsetof(Socket, writable), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KeepAlive", "b", bus_property_get_bool, offsetof(Socket, keep_alive), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KeepAliveTimeUSec", "t", bus_property_get_usec, offsetof(Socket, keep_alive_time), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KeepAliveIntervalUSec", "t", bus_property_get_usec, offsetof(Socket, keep_alive_interval), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KeepAliveProbes", "u", bus_property_get_unsigned, offsetof(Socket, keep_alive_cnt), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DeferAcceptUSec" , "t", bus_property_get_usec, offsetof(Socket, defer_accept), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NoDelay", "b", bus_property_get_bool, offsetof(Socket, no_delay), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Priority", "i", bus_property_get_int, offsetof(Socket, priority), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReceiveBuffer", "t", bus_property_get_size, offsetof(Socket, receive_buffer), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SendBuffer", "t", bus_property_get_size, offsetof(Socket, send_buffer), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IPTOS", "i", bus_property_get_int, offsetof(Socket, ip_tos), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IPTTL", "i", bus_property_get_int, offsetof(Socket, ip_ttl), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PipeSize", "t", bus_property_get_size, offsetof(Socket, pipe_size), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FreeBind", "b", bus_property_get_bool, offsetof(Socket, free_bind), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Transparent", "b", bus_property_get_bool, offsetof(Socket, transparent), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Broadcast", "b", bus_property_get_bool, offsetof(Socket, broadcast), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PassCredentials", "b", bus_property_get_bool, offsetof(Socket, pass_cred), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PassSecurity", "b", bus_property_get_bool, offsetof(Socket, pass_sec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RemoveOnStop", "b", bus_property_get_bool, offsetof(Socket, remove_on_stop), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Listen", "a(ss)", property_get_listen, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Symlinks", "as", NULL, offsetof(Socket, symlinks), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Mark", "i", bus_property_get_int, offsetof(Socket, mark), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MaxConnections", "u", bus_property_get_unsigned, offsetof(Socket, max_connections), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MaxConnectionsPerSource", "u", bus_property_get_unsigned, offsetof(Socket, max_connections_per_source), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MessageQueueMaxMessages", "x", bus_property_get_long, offsetof(Socket, mq_maxmsg), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MessageQueueMessageSize", "x", bus_property_get_long, offsetof(Socket, mq_msgsize), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TCPCongestion", "s", NULL, offsetof(Socket, tcp_congestion), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReusePort", "b",  bus_property_get_bool, offsetof(Socket, reuse_port), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SmackLabel", "s", NULL, offsetof(Socket, smack), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SmackLabelIPIn", "s", NULL, offsetof(Socket, smack_ip_in), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SmackLabelIPOut", "s", NULL, offsetof(Socket, smack_ip_out), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Socket, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Socket, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NConnections", "u", bus_property_get_unsigned, offsetof(Socket, n_connections), 0),
        SD_BUS_PROPERTY("NAccepted", "u", bus_property_get_unsigned, offsetof(Socket, n_accepted), 0),
        SD_BUS_PROPERTY("FileDescriptorName", "s", property_get_fdname, 0, 0),
        SD_BUS_PROPERTY("SocketProtocol", "i", bus_property_get_int, offsetof(Socket, socket_protocol), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TriggerLimitIntervalUSec", "t", bus_property_get_usec, offsetof(Socket, trigger_limit.interval), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TriggerLimitBurst", "u", bus_property_get_unsigned, offsetof(Socket, trigger_limit.burst), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UID", "u", NULL, offsetof(Unit, ref_uid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("GID", "u", NULL, offsetof(Unit, ref_gid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPre", offsetof(Socket, exec_command[SOCKET_EXEC_START_PRE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPost", offsetof(Socket, exec_command[SOCKET_EXEC_START_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStopPre", offsetof(Socket, exec_command[SOCKET_EXEC_STOP_PRE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStopPost", offsetof(Socket, exec_command[SOCKET_EXEC_STOP_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

static int bus_socket_set_transient_property(
                Socket *s,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        SocketExecCommand ci;
        Unit *u = UNIT(s);
        int r;

        assert(s);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (STR_IN_SET(name,
                       "Accept", "Writable", "KeepAlive", "NoDelay", "FreeBind", "Transparent", "Broadcast",
                       "PassCredentials", "PassSecurity", "ReusePort", "RemoveOnStop", "SELinuxContextFromNet")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (streq(name, "Accept"))
                                s->accept = b;
                        else if (streq(name, "Writable"))
                                s->writable = b;
                        else if (streq(name, "KeepAlive"))
                                s->keep_alive = b;
                        else if (streq(name, "NoDelay"))
                                s->no_delay = b;
                        else if (streq(name, "FreeBind"))
                                s->free_bind = b;
                        else if (streq(name, "Transparent"))
                                s->transparent = b;
                        else if (streq(name, "Broadcast"))
                                s->broadcast = b;
                        else if (streq(name, "PassCredentials"))
                                s->pass_cred = b;
                        else if (streq(name, "PassSecurity"))
                                s->pass_sec = b;
                        else if (streq(name, "ReusePort"))
                                s->reuse_port = b;
                        else if (streq(name, "RemoveOnStop"))
                                s->remove_on_stop = b;
                        else /* "SELinuxContextFromNet" */
                                s->selinux_context_from_net = b;

                        unit_write_settingf(u, flags, name, "%s=%s", name, yes_no(b));
                }

                return 1;

        } else if (STR_IN_SET(name, "Priority", "IPTTL", "Mark")) {
                int32_t i;

                r = sd_bus_message_read(message, "i", &i);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (streq(name, "Priority"))
                                s->priority = i;
                        else if (streq(name, "IPTTL"))
                                s->ip_ttl = i;
                        else /* "Mark" */
                                s->mark = i;

                        unit_write_settingf(u, flags, name, "%s=%i", name, i);
                }

                return 1;

        } else if (streq(name, "IPTOS")) {
                _cleanup_free_ char *str = NULL;
                int32_t i;

                r = sd_bus_message_read(message, "i", &i);
                if (r < 0)
                        return r;

                r = ip_tos_to_string_alloc(i, &str);
                if (r < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid %s: %i", name, i);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        s->ip_tos = i;

                        unit_write_settingf(u, flags, name, "%s=%s", name, str);
                }

                return 1;

        } else if (streq(name, "SocketProtocol")) {
                int32_t i;

                r = sd_bus_message_read(message, "i", &i);
                if (r < 0)
                        return r;

                if (!IN_SET(i, IPPROTO_UDPLITE, IPPROTO_SCTP))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid %s: %i", name, i);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        s->socket_protocol = i;
                        unit_write_settingf(u, flags, name, "%s=%s", name, i == IPPROTO_UDPLITE ? "udplite" : "sctp");
                }

                return 1;

        } else if (STR_IN_SET(name, "Backlog", "MaxConnections", "MaxConnectionsPerSource", "KeepAliveProbes", "TriggerLimitBurst")) {
                uint32_t n;

                r = sd_bus_message_read(message, "u", &n);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (streq(name, "Backlog"))
                                s->backlog = n;
                        else if (streq(name, "MaxConnections"))
                                s->max_connections = n;
                        else if (streq(name, "MaxConnectionsPerSource"))
                                s->max_connections_per_source = n;
                        else if (streq(name, "KeepAliveProbes"))
                                s->keep_alive_cnt = n;
                        else /* "TriggerLimitBurst" */
                                s->trigger_limit.burst = n;

                        unit_write_settingf(u, flags, name, "%s=%u", name, n);
                }

                return 1;

        } else if (STR_IN_SET(name, "SocketMode", "DirectoryMode")) {
                mode_t m;

                r = sd_bus_message_read(message, "u", &m);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (streq(name, "SocketMode"))
                                s->socket_mode = m;
                        else /* "DirectoryMode" */
                                s->directory_mode = m;

                        unit_write_settingf(u, flags, name, "%s=%040o", name, m);
                }

                return 1;

        } else if (STR_IN_SET(name, "MessageQueueMaxMessages", "MessageQueueMessageSize")) {
                int64_t n;

                r = sd_bus_message_read(message, "x", &n);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (streq(name, "MessageQueueMaxMessages"))
                                s->mq_maxmsg = (long) n;
                        else /* "MessageQueueMessageSize" */
                                s->mq_msgsize = (long) n;

                        unit_write_settingf(u, flags, name, "%s=%" PRIi64, name, n);
                }

                return 1;

        } else if (STR_IN_SET(name, "TimeoutUSec", "KeepAliveTimeUSec", "KeepAliveIntervalUSec", "DeferAcceptUSec", "TriggerLimitIntervalUSec")) {
                usec_t t;

                r = sd_bus_message_read(message, "t", &t);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (streq(name, "TimeoutUSec"))
                                s->timeout_usec = t ?: USEC_INFINITY;
                        else if (streq(name, "KeepAliveTimeUSec"))
                                s->keep_alive_time = t;
                        else if (streq(name, "KeepAliveIntervalUSec"))
                                s->keep_alive_interval = t;
                        else if (streq(name, "DeferAcceptUSec"))
                                s->defer_accept = t;
                        else /* "TriggerLimitIntervalUSec" */
                                s->trigger_limit.interval = t;

                        unit_write_settingf(u, flags, name, "%s=" USEC_FMT, name, t);
                }

                return 1;

        } else if (STR_IN_SET(name, "ReceiveBuffer", "SendBuffer", "PipeSize")) {
                uint64_t t;

                r = sd_bus_message_read(message, "t", &t);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (streq(name, "ReceiveBuffer"))
                                s->receive_buffer = t;
                        else if (streq(name, "SendBuffer"))
                                s->send_buffer = t;
                        else /* "PipeSize" */
                                s->pipe_size = t;

                        unit_write_settingf(u, flags, name, "%s=%" PRIu64, name, t);
                }

                return 1;

        } else if (STR_IN_SET(name, "SmackLabel", "SmackLabelIPIn", "SmackLabelIPOut", "TCPCongestion")) {
                const char *n;

                r = sd_bus_message_read(message, "s", &n);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {

                        if (streq(name, "SmackLabel"))
                                r = free_and_strdup(&s->smack, empty_to_null(n));
                        else if (streq(name, "SmackLabelIPin"))
                                r = free_and_strdup(&s->smack_ip_in, empty_to_null(n));
                        else if (streq(name, "SmackLabelIPOut"))
                                r = free_and_strdup(&s->smack_ip_out, empty_to_null(n));
                        else /* "TCPCongestion" */
                                r = free_and_strdup(&s->tcp_congestion, empty_to_null(n));
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", name, strempty(n));
                }

                return 1;

        } else if (streq(name, "BindToDevice")) {
                const char *n;

                r = sd_bus_message_read(message, "s", &n);
                if (r < 0)
                        return r;

                if (n[0] && !streq(n, "*")) {
                        if (!ifname_valid(n))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface name for %s: %s", name, n);
                } else
                        n = NULL;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {

                        r = free_and_strdup(&s->bind_to_device, empty_to_null(n));
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", name, strempty(n));
                }

                return 1;

        } else if (streq(name, "BindIPv6Only")) {
                SocketAddressBindIPv6Only b;
                const char *n;

                r = sd_bus_message_read(message, "s", &n);
                if (r < 0)
                        return r;

                b = socket_address_bind_ipv6_only_from_string(n);
                if (b < 0) {
                        r = parse_boolean(n);
                        if (r < 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid %s: %s", name, n);

                        b = r ? SOCKET_ADDRESS_IPV6_ONLY : SOCKET_ADDRESS_BOTH;
                }

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        s->bind_ipv6_only = b;
                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", name, n);
                }

                return 1;

        } else if (streq(name, "FileDescriptorName")) {
                const char *n;

                r = sd_bus_message_read(message, "s", &n);
                if (r < 0)
                        return r;

                if (!isempty(n) && !fdname_is_valid(n))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid %s: %s", name, n);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        r = free_and_strdup(&s->fdname, empty_to_null(n));
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", name, strempty(n));
                }

                return 1;

        } else if (STR_IN_SET(name, "SocketUser", "SocketGroup")) {
                const char *n;

                r = sd_bus_message_read(message, "s", &n);
                if (r < 0)
                        return r;

                if (!isempty(n) && !valid_user_group_name_or_id(n))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid %s: %s", name, n);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {

                        if (streq(name, "SocketUser"))
                                r = free_and_strdup(&s->user, empty_to_null(n));
                        else /* "SocketGroup" */
                                r = free_and_strdup(&s->user, empty_to_null(n));
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", name, strempty(n));
                }

                return 1;

        } else if (streq(name, "Symlinks")) {
                _cleanup_strv_free_ char **l = NULL;
                char **p;

                r = sd_bus_message_read_strv(message, &l);
                if (r < 0)
                        return r;

                STRV_FOREACH(p, l) {
                        if (!utf8_is_valid(*p))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "String is not UTF-8 clean, ignoring assignment: %s", *p);

                        if (!path_is_absolute(*p))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Symlink path is not absolute: %s", *p);
                }

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (strv_isempty(l)) {
                                s->symlinks = strv_free(s->symlinks);
                                unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=", name);
                        } else {
                                _cleanup_free_ char *joined = NULL;

                                r = strv_extend_strv(&s->symlinks, l, true);
                                if (r < 0)
                                        return -ENOMEM;

                                joined = strv_join(l, " ");
                                if (!joined)
                                        return -ENOMEM;

                                unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", name, joined);
                        }
                }

                return 1;

        } else if (streq(name, "Listen")) {
                const char *t, *a;
                bool empty = true;

                r = sd_bus_message_enter_container(message, 'a', "(ss)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(ss)", &t, &a)) > 0) {
                        _cleanup_free_ SocketPort *p = NULL;

                        p = new0(SocketPort, 1);
                        if (!p)
                                return log_oom();

                        p->type = socket_type_from_string(t);
                        if (p->type < 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown Socket type: %s", t);

                        if (p->type != SOCKET_SOCKET) {
                                p->path = strdup(a);
                                path_kill_slashes(p->path);

                        } else if (streq(t, "Netlink")) {
                                r = socket_address_parse_netlink(&p->address, a);
                                if (r < 0)
                                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid netlink address: %s", a);

                        } else {
                                r = socket_address_parse(&p->address, a);
                                if (r < 0)
                                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid address: %s", a);

                                p->address.type = socket_address_type_from_string(t);
                                if (p->address.type < 0)
                                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid address type: %s", t);

                                if (socket_address_family(&p->address) != AF_LOCAL && p->address.type == SOCK_SEQPACKET)
                                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Address family not supported: %s", a);
                        }

                        p->fd = -1;
                        p->auxiliary_fds = NULL;
                        p->n_auxiliary_fds = 0;
                        p->socket = s;

                        empty = false;

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                SocketPort *tail;

                                LIST_FIND_TAIL(port, s->ports, tail);
                                LIST_INSERT_AFTER(port, s->ports, tail, p);

                                p = NULL;

                                unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "Listen%s=%s", t, a);
                        }
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags) && empty) {
                        socket_free_ports(s);
                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "ListenStream=");
                }

                return 1;

        } else if ((ci = socket_exec_command_from_string(name)) >= 0)
                return bus_exec_command_set_transient_property(UNIT(s), name, &s->exec_command[ci], message, flags, error);

        return 0;
}

int bus_socket_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Socket *s = SOCKET(u);
        int r;

        assert(s);
        assert(name);
        assert(message);

        assert(s);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, message, flags, error);
        if (r != 0)
                return r;

        if (u->transient && u->load_state == UNIT_STUB) {
                /* This is a transient unit, let's load a little more */

                r = bus_socket_set_transient_property(s, name, message, flags, error);
                if (r != 0)
                        return r;

                r = bus_exec_context_set_transient_property(u, &s->exec_context, name, message, flags, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &s->kill_context, name, message, flags, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_socket_commit_properties(Unit *u) {
        assert(u);

        unit_update_cgroup_members_masks(u);
        unit_realize_cgroup(u);

        return 0;
}
