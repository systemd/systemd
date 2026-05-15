/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "ip-protocol-list.h"
#include "json-util.h"
#include "socket.h"
#include "user-util.h"
#include "varlink-common.h"
#include "varlink-socket.h"

static int socket_listen_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Socket *s = ASSERT_PTR(SOCKET(userdata));
        int r;

        assert(ret);

        LIST_FOREACH(port, p, s->ports) {
                _cleanup_free_ char *address = NULL;

                r = socket_port_to_address(p, &address);
                if (r < 0)
                        return log_debug_errno(r, "Failed to call socket_port_to_address(): %m");

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("type", socket_port_type_to_string(p)),
                                SD_JSON_BUILD_PAIR_STRING("address", address));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int socket_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Socket *s = ASSERT_PTR(SOCKET(userdata));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Listen", socket_listen_build_json, s),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SocketProtocol", ip_protocol_to_name(s->socket_protocol)),
                        JSON_BUILD_PAIR_ENUM("BindIPv6Only", socket_address_bind_ipv6_only_to_string(s->bind_ipv6_only)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Backlog", s->backlog),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("BindToDevice", s->bind_to_device),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SocketUser", s->user),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SocketGroup", s->group),
                        SD_JSON_BUILD_PAIR_UNSIGNED("SocketMode", s->socket_mode),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", s->directory_mode),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Accept", s->accept),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Writable", s->writable),
                        SD_JSON_BUILD_PAIR_BOOLEAN("FlushPending", s->flush_pending),
                        SD_JSON_BUILD_PAIR_UNSIGNED("MaxConnections", s->max_connections),
                        SD_JSON_BUILD_PAIR_UNSIGNED("MaxConnectionsPerSource", s->max_connections_per_source),
                        SD_JSON_BUILD_PAIR_BOOLEAN("KeepAlive", s->keep_alive),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("KeepAliveTimeUSec", s->keep_alive_time),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("KeepAliveIntervalUSec", s->keep_alive_interval),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("KeepAliveProbes", s->keep_alive_cnt),
                        SD_JSON_BUILD_PAIR_BOOLEAN("NoDelay", s->no_delay),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("Priority", s->priority),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("DeferAcceptUSec", s->defer_accept),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ReceiveBuffer", s->receive_buffer),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("SendBuffer", s->send_buffer),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("IPTOS", s->ip_tos),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("IPTTL", s->ip_ttl),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("Mark", s->mark),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ReusePort", s->reuse_port),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SmackLabel", s->smack),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SmackLabelIPIn", s->smack_ip_in),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SmackLabelIPOut", s->smack_ip_out),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SELinuxContextFromNet", s->selinux_context_from_net),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("PipeSize", s->pipe_size),
                        JSON_BUILD_PAIR_INTEGER_NON_ZERO("MessageQueueMaxMessages", s->mq_maxmsg),
                        JSON_BUILD_PAIR_INTEGER_NON_ZERO("MessageQueueMessageSize", s->mq_msgsize),
                        SD_JSON_BUILD_PAIR_BOOLEAN("FreeBind", s->free_bind),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Transparent", s->transparent),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Broadcast", s->broadcast),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PassCredentials", s->pass_cred),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PassPIDFD", s->pass_pidfd),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PassSecurity", s->pass_sec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PassPacketInfo", s->pass_pktinfo),
                        SD_JSON_BUILD_PAIR_BOOLEAN("AcceptFileDescriptors", s->pass_rights),
                        JSON_BUILD_PAIR_ENUM("Timestamping", socket_timestamping_to_string(s->timestamping)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("TCPCongestion", s->tcp_congestion),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStartPre", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_START_PRE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStartPost", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_START_POST]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStopPre", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_STOP_PRE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStopPost", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_STOP_POST]),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutUSec", s->timeout_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemoveOnStop", s->remove_on_stop),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Symlinks", s->symlinks),
                        SD_JSON_BUILD_PAIR_STRING("FileDescriptorName", socket_fdname(s)),
                        JSON_BUILD_PAIR_RATELIMIT("TriggerLimit", &s->trigger_limit),
                        JSON_BUILD_PAIR_RATELIMIT("PollLimit", &s->poll_limit),
                        JSON_BUILD_PAIR_ENUM("DeferTrigger", socket_defer_trigger_to_string(s->defer_trigger)),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("DeferTriggerMaxUSec", s->defer_trigger_max_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PassFileDescriptorsToExec", s->pass_fds_to_exec));
}

int socket_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Socket *s = ASSERT_PTR(SOCKET(u));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(&s->control_pid), "ControlPID", JSON_BUILD_PIDREF(&s->control_pid)),
                        JSON_BUILD_PAIR_ENUM("Result", socket_result_to_string(s->result)),
                        JSON_BUILD_PAIR_ENUM("CleanResult", socket_result_to_string(s->clean_result)),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("NConnections", s->n_connections),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("NAccepted", s->n_accepted),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("NRefused", s->n_refused),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(u->ref_uid), "UID", SD_JSON_BUILD_UNSIGNED(u->ref_uid)),
                        SD_JSON_BUILD_PAIR_CONDITION(gid_is_valid(u->ref_gid), "GID", SD_JSON_BUILD_UNSIGNED(u->ref_gid)));
}
