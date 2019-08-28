/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bus-util.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-socket.h"
#include "dbus-util.h"
#include "fd-util.h"
#include "ip-protocol-list.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket.h"
#include "socket-util.h"
#include "string-util.h"
#include "unit.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, socket_result, SocketResult);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_bind_ipv6_only, socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);
static BUS_DEFINE_PROPERTY_GET(property_get_fdname, "s", Socket, socket_fdname);

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
        SD_BUS_PROPERTY("NRefused", "u", bus_property_get_unsigned, offsetof(Socket, n_refused), 0),
        SD_BUS_PROPERTY("FileDescriptorName", "s", property_get_fdname, 0, 0),
        SD_BUS_PROPERTY("SocketProtocol", "i", bus_property_get_int, offsetof(Socket, socket_protocol), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TriggerLimitIntervalUSec", "t", bus_property_get_usec, offsetof(Socket, trigger_limit.interval), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TriggerLimitBurst", "u", bus_property_get_unsigned, offsetof(Socket, trigger_limit.burst), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UID", "u", bus_property_get_uid, offsetof(Unit, ref_uid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("GID", "u", bus_property_get_gid, offsetof(Unit, ref_gid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPre", offsetof(Socket, exec_command[SOCKET_EXEC_START_PRE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPost", offsetof(Socket, exec_command[SOCKET_EXEC_START_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStopPre", offsetof(Socket, exec_command[SOCKET_EXEC_STOP_PRE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStopPost", offsetof(Socket, exec_command[SOCKET_EXEC_STOP_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

static bool check_size_t_truncation(uint64_t t) {
        return (size_t) t == t;
}

static const char* socket_protocol_to_string(int32_t i) {
        if (i == IPPROTO_IP)
                return "";

        if (!IN_SET(i, IPPROTO_UDPLITE, IPPROTO_SCTP))
                return NULL;

        return ip_protocol_to_name(i);
}

static BUS_DEFINE_SET_TRANSIENT(int, "i", int32_t, int, "%" PRIi32);
static BUS_DEFINE_SET_TRANSIENT(message_queue, "x", int64_t, long, "%" PRIi64);
static BUS_DEFINE_SET_TRANSIENT_IS_VALID(size_t_check_truncation, "t", uint64_t, size_t, "%" PRIu64, check_size_t_truncation);
static BUS_DEFINE_SET_TRANSIENT_PARSE(bind_ipv6_only, SocketAddressBindIPv6Only, socket_address_bind_ipv6_only_or_bool_from_string);
static BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(fdname, fdname_is_valid);
static BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(ifname, ifname_valid);
static BUS_DEFINE_SET_TRANSIENT_TO_STRING_ALLOC(ip_tos, "i", int32_t, int, "%" PRIi32, ip_tos_to_string_alloc);
static BUS_DEFINE_SET_TRANSIENT_TO_STRING(socket_protocol, "i", int32_t, int, "%" PRIi32, socket_protocol_to_string);

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

        if (streq(name, "Accept"))
                return bus_set_transient_bool(u, name, &s->accept, message, flags, error);

        if (streq(name, "Writable"))
                return bus_set_transient_bool(u, name, &s->writable, message, flags, error);

        if (streq(name, "KeepAlive"))
                return bus_set_transient_bool(u, name, &s->keep_alive, message, flags, error);

        if (streq(name, "NoDelay"))
                return bus_set_transient_bool(u, name, &s->no_delay, message, flags, error);

        if (streq(name, "FreeBind"))
                return bus_set_transient_bool(u, name, &s->free_bind, message, flags, error);

        if (streq(name, "Transparent"))
                return bus_set_transient_bool(u, name, &s->transparent, message, flags, error);

        if (streq(name, "Broadcast"))
                return bus_set_transient_bool(u, name, &s->broadcast, message, flags, error);

        if (streq(name, "PassCredentials"))
                return bus_set_transient_bool(u, name, &s->pass_cred, message, flags, error);

        if (streq(name, "PassSecurity"))
                return bus_set_transient_bool(u, name, &s->pass_sec, message, flags, error);

        if (streq(name, "ReusePort"))
                return bus_set_transient_bool(u, name, &s->reuse_port, message, flags, error);

        if (streq(name, "RemoveOnStop"))
                return bus_set_transient_bool(u, name, &s->remove_on_stop, message, flags, error);

        if (streq(name, "SELinuxContextFromNet"))
                return bus_set_transient_bool(u, name, &s->selinux_context_from_net, message, flags, error);

        if (streq(name, "Priority"))
                return bus_set_transient_int(u, name, &s->priority, message, flags, error);

        if (streq(name, "IPTTL"))
                return bus_set_transient_int(u, name, &s->ip_ttl, message, flags, error);

        if (streq(name, "Mark"))
                return bus_set_transient_int(u, name, &s->mark, message, flags, error);

        if (streq(name, "Backlog"))
                return bus_set_transient_unsigned(u, name, &s->backlog, message, flags, error);

        if (streq(name, "MaxConnections"))
                return bus_set_transient_unsigned(u, name, &s->max_connections, message, flags, error);

        if (streq(name, "MaxConnectionsPerSource"))
                return bus_set_transient_unsigned(u, name, &s->max_connections_per_source, message, flags, error);

        if (streq(name, "KeepAliveProbes"))
                return bus_set_transient_unsigned(u, name, &s->keep_alive_cnt, message, flags, error);

        if (streq(name, "TriggerLimitBurst"))
                return bus_set_transient_unsigned(u, name, &s->trigger_limit.burst, message, flags, error);

        if (streq(name, "SocketMode"))
                return bus_set_transient_mode_t(u, name, &s->socket_mode, message, flags, error);

        if (streq(name, "DirectoryMode"))
                return bus_set_transient_mode_t(u, name, &s->directory_mode, message, flags, error);

        if (streq(name, "MessageQueueMaxMessages"))
                return bus_set_transient_message_queue(u, name, &s->mq_maxmsg, message, flags, error);

        if (streq(name, "MessageQueueMessageSize"))
                return bus_set_transient_message_queue(u, name, &s->mq_msgsize, message, flags, error);

        if (streq(name, "TimeoutUSec"))
                return bus_set_transient_usec_fix_0(u, name, &s->timeout_usec, message, flags, error);

        if (streq(name, "KeepAliveTimeUSec"))
                return bus_set_transient_usec(u, name, &s->keep_alive_time, message, flags, error);

        if (streq(name, "KeepAliveIntervalUSec"))
                return bus_set_transient_usec(u, name, &s->keep_alive_interval, message, flags, error);

        if (streq(name, "DeferAcceptUSec"))
                return bus_set_transient_usec(u, name, &s->defer_accept, message, flags, error);

        if (streq(name, "TriggerLimitIntervalUSec"))
                return bus_set_transient_usec(u, name, &s->trigger_limit.interval, message, flags, error);

        if (streq(name, "SmackLabel"))
                return bus_set_transient_string(u, name, &s->smack, message, flags, error);

        if (streq(name, "SmackLabelIPin"))
                return bus_set_transient_string(u, name, &s->smack_ip_in, message, flags, error);

        if (streq(name, "SmackLabelIPOut"))
                return bus_set_transient_string(u, name, &s->smack_ip_out, message, flags, error);

        if (streq(name, "TCPCongestion"))
                return bus_set_transient_string(u, name, &s->tcp_congestion, message, flags, error);

        if (streq(name, "FileDescriptorName"))
                return bus_set_transient_fdname(u, name, &s->fdname, message, flags, error);

        if (streq(name, "SocketUser"))
                return bus_set_transient_user_compat(u, name, &s->user, message, flags, error);

        if (streq(name, "SocketGroup"))
                return bus_set_transient_user_compat(u, name, &s->group, message, flags, error);

        if (streq(name, "BindIPv6Only"))
                return bus_set_transient_bind_ipv6_only(u, name, &s->bind_ipv6_only, message, flags, error);

        if (streq(name, "ReceiveBuffer"))
                return bus_set_transient_size_t_check_truncation(u, name, &s->receive_buffer, message, flags, error);

        if (streq(name, "SendBuffer"))
                return bus_set_transient_size_t_check_truncation(u, name, &s->send_buffer, message, flags, error);

        if (streq(name, "PipeSize"))
                return bus_set_transient_size_t_check_truncation(u, name, &s->pipe_size, message, flags, error);

        if (streq(name, "BindToDevice"))
                return bus_set_transient_ifname(u, name, &s->bind_to_device, message, flags, error);

        if (streq(name, "IPTOS"))
                return bus_set_transient_ip_tos(u, name, &s->ip_tos, message, flags, error);

        if (streq(name, "SocketProtocol"))
                return bus_set_transient_socket_protocol(u, name, &s->socket_protocol, message, flags, error);

        ci = socket_exec_command_from_string(name);
        if (ci >= 0)
                return bus_set_transient_exec_command(u, name,
                                                      &s->exec_command[ci],
                                                      message, flags, error);

        if (streq(name, "Symlinks")) {
                _cleanup_strv_free_ char **l = NULL;
                char **p;

                r = sd_bus_message_read_strv(message, &l);
                if (r < 0)
                        return r;

                STRV_FOREACH(p, l) {
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

                        p = new(SocketPort, 1);
                        if (!p)
                                return log_oom();

                        *p = (SocketPort) {
                                .fd = -1,
                                .socket = s,
                        };

                        p->type = socket_port_type_from_string(t);
                        if (p->type < 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown Socket type: %s", t);

                        if (p->type != SOCKET_SOCKET) {
                                if (!path_is_valid(p->path))
                                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid socket path: %s", t);

                                p->path = strdup(a);
                                if (!p->path)
                                        return log_oom();

                                path_simplify(p->path, false);

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

                        empty = false;

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                LIST_APPEND(port, s->ports, TAKE_PTR(p));
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
        }

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

        unit_invalidate_cgroup_members_masks(u);
        unit_realize_cgroup(u);

        return 0;
}
