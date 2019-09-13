/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/sctp.h>

#include "alloc-util.h"
#include "bpf-firewall.h"
#include "bus-error.h"
#include "bus-util.h"
#include "copy.h"
#include "dbus-socket.h"
#include "dbus-unit.h"
#include "def.h"
#include "exit-status.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "ip-protocol-list.h"
#include "label.h"
#include "log.h"
#include "missing.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "serialize.h"
#include "signal-util.h"
#include "smack-util.h"
#include "socket.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"
#include "user-util.h"

struct SocketPeer {
        unsigned n_ref;

        Socket *socket;
        union sockaddr_union peer;
        socklen_t peer_salen;
};

static const UnitActiveState state_translation_table[_SOCKET_STATE_MAX] = {
        [SOCKET_DEAD] = UNIT_INACTIVE,
        [SOCKET_START_PRE] = UNIT_ACTIVATING,
        [SOCKET_START_CHOWN] = UNIT_ACTIVATING,
        [SOCKET_START_POST] = UNIT_ACTIVATING,
        [SOCKET_LISTENING] = UNIT_ACTIVE,
        [SOCKET_RUNNING] = UNIT_ACTIVE,
        [SOCKET_STOP_PRE] = UNIT_DEACTIVATING,
        [SOCKET_STOP_PRE_SIGTERM] = UNIT_DEACTIVATING,
        [SOCKET_STOP_PRE_SIGKILL] = UNIT_DEACTIVATING,
        [SOCKET_STOP_POST] = UNIT_DEACTIVATING,
        [SOCKET_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SOCKET_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SOCKET_FAILED] = UNIT_FAILED,
        [SOCKET_CLEANING] = UNIT_MAINTENANCE,
};

static int socket_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int socket_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);

static void socket_init(Unit *u) {
        Socket *s = SOCKET(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        s->backlog = SOMAXCONN;
        s->timeout_usec = u->manager->default_timeout_start_usec;
        s->directory_mode = 0755;
        s->socket_mode = 0666;

        s->max_connections = 64;

        s->priority = -1;
        s->ip_tos = -1;
        s->ip_ttl = -1;
        s->mark = -1;

        s->exec_context.std_output = u->manager->default_std_output;
        s->exec_context.std_error = u->manager->default_std_error;

        s->control_command_id = _SOCKET_EXEC_COMMAND_INVALID;

        s->trigger_limit.interval = USEC_INFINITY;
        s->trigger_limit.burst = (unsigned) -1;
}

static void socket_unwatch_control_pid(Socket *s) {
        assert(s);

        if (s->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(s), s->control_pid);
        s->control_pid = 0;
}

static void socket_cleanup_fd_list(SocketPort *p) {
        assert(p);

        close_many(p->auxiliary_fds, p->n_auxiliary_fds);
        p->auxiliary_fds = mfree(p->auxiliary_fds);
        p->n_auxiliary_fds = 0;
}

void socket_free_ports(Socket *s) {
        SocketPort *p;

        assert(s);

        while ((p = s->ports)) {
                LIST_REMOVE(port, s->ports, p);

                sd_event_source_unref(p->event_source);

                socket_cleanup_fd_list(p);
                safe_close(p->fd);
                free(p->path);
                free(p);
        }
}

static void socket_done(Unit *u) {
        Socket *s = SOCKET(u);
        SocketPeer *p;

        assert(s);

        socket_free_ports(s);

        while ((p = set_steal_first(s->peers_by_address)))
                p->socket = NULL;

        s->peers_by_address = set_free(s->peers_by_address);

        s->exec_runtime = exec_runtime_unref(s->exec_runtime, false);
        exec_command_free_array(s->exec_command, _SOCKET_EXEC_COMMAND_MAX);
        s->control_command = NULL;

        dynamic_creds_unref(&s->dynamic_creds);

        socket_unwatch_control_pid(s);

        unit_ref_unset(&s->service);

        s->tcp_congestion = mfree(s->tcp_congestion);
        s->bind_to_device = mfree(s->bind_to_device);

        s->smack = mfree(s->smack);
        s->smack_ip_in = mfree(s->smack_ip_in);
        s->smack_ip_out = mfree(s->smack_ip_out);

        strv_free(s->symlinks);

        s->user = mfree(s->user);
        s->group = mfree(s->group);

        s->fdname = mfree(s->fdname);

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);
}

static int socket_arm_timer(Socket *s, usec_t usec) {
        int r;

        assert(s);

        if (s->timer_event_source) {
                r = sd_event_source_set_time(s->timer_event_source, usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(s->timer_event_source, SD_EVENT_ONESHOT);
        }

        if (usec == USEC_INFINITY)
                return 0;

        r = sd_event_add_time(
                        UNIT(s)->manager->event,
                        &s->timer_event_source,
                        CLOCK_MONOTONIC,
                        usec, 0,
                        socket_dispatch_timer, s);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s->timer_event_source, "socket-timer");

        return 0;
}

int socket_instantiate_service(Socket *s) {
        _cleanup_free_ char *prefix = NULL, *name = NULL;
        int r;
        Unit *u;

        assert(s);

        /* This fills in s->service if it isn't filled in yet. For
         * Accept=yes sockets we create the next connection service
         * here. For Accept=no this is mostly a NOP since the service
         * is figured out at load time anyway. */

        if (UNIT_DEREF(s->service))
                return 0;

        if (!s->accept)
                return 0;

        r = unit_name_to_prefix(UNIT(s)->id, &prefix);
        if (r < 0)
                return r;

        if (asprintf(&name, "%s@%u.service", prefix, s->n_accepted) < 0)
                return -ENOMEM;

        r = manager_load_unit(UNIT(s)->manager, name, NULL, NULL, &u);
        if (r < 0)
                return r;

        unit_ref_set(&s->service, UNIT(s), u);

        return unit_add_two_dependencies(UNIT(s), UNIT_BEFORE, UNIT_TRIGGERS, u, false, UNIT_DEPENDENCY_IMPLICIT);
}

static bool have_non_accept_socket(Socket *s) {
        SocketPort *p;

        assert(s);

        if (!s->accept)
                return true;

        LIST_FOREACH(port, p, s->ports) {

                if (p->type != SOCKET_SOCKET)
                        return true;

                if (!socket_address_can_accept(&p->address))
                        return true;
        }

        return false;
}

static int socket_add_mount_dependencies(Socket *s) {
        SocketPort *p;
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                const char *path = NULL;

                if (p->type == SOCKET_SOCKET)
                        path = socket_address_get_path(&p->address);
                else if (IN_SET(p->type, SOCKET_FIFO, SOCKET_SPECIAL, SOCKET_USB_FUNCTION))
                        path = p->path;

                if (!path)
                        continue;

                r = unit_require_mounts_for(UNIT(s), path, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int socket_add_device_dependencies(Socket *s) {
        char *t;

        assert(s);

        if (!s->bind_to_device || streq(s->bind_to_device, "lo"))
                return 0;

        t = strjoina("/sys/subsystem/net/devices/", s->bind_to_device);
        return unit_add_node_dependency(UNIT(s), t, false, UNIT_BINDS_TO, UNIT_DEPENDENCY_FILE);
}

static int socket_add_default_dependencies(Socket *s) {
        int r;
        assert(s);

        if (!UNIT(s)->default_dependencies)
                return 0;

        r = unit_add_dependency_by_name(UNIT(s), UNIT_BEFORE, SPECIAL_SOCKETS_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(UNIT(s)->manager)) {
                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
                if (r < 0)
                        return r;
        }

        return unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
}

_pure_ static bool socket_has_exec(Socket *s) {
        unsigned i;
        assert(s);

        for (i = 0; i < _SOCKET_EXEC_COMMAND_MAX; i++)
                if (s->exec_command[i])
                        return true;

        return false;
}

static int socket_add_extras(Socket *s) {
        Unit *u = UNIT(s);
        int r;

        assert(s);

        /* Pick defaults for the trigger limit, if nothing was explicitly configured. We pick a relatively high limit
         * in Accept=yes mode, and a lower limit for Accept=no. Reason: in Accept=yes mode we are invoking accept()
         * ourselves before the trigger limit can hit, thus incoming connections are taken off the socket queue quickly
         * and reliably. This is different for Accept=no, where the spawned service has to take the incoming traffic
         * off the queues, which it might not necessarily do. Moreover, while Accept=no services are supposed to
         * process whatever is queued in one go, and thus should normally never have to be started frequently. This is
         * different for Accept=yes where each connection is processed by a new service instance, and thus frequent
         * service starts are typical. */

        if (s->trigger_limit.interval == USEC_INFINITY)
                s->trigger_limit.interval = 2 * USEC_PER_SEC;

        if (s->trigger_limit.burst == (unsigned) -1) {
                if (s->accept)
                        s->trigger_limit.burst = 200;
                else
                        s->trigger_limit.burst = 20;
        }

        if (have_non_accept_socket(s)) {

                if (!UNIT_DEREF(s->service)) {
                        Unit *x;

                        r = unit_load_related_unit(u, ".service", &x);
                        if (r < 0)
                                return r;

                        unit_ref_set(&s->service, u, x);
                }

                r = unit_add_two_dependencies(u, UNIT_BEFORE, UNIT_TRIGGERS, UNIT_DEREF(s->service), true, UNIT_DEPENDENCY_IMPLICIT);
                if (r < 0)
                        return r;
        }

        r = socket_add_mount_dependencies(s);
        if (r < 0)
                return r;

        r = socket_add_device_dependencies(s);
        if (r < 0)
                return r;

        r = unit_patch_contexts(u);
        if (r < 0)
                return r;

        if (socket_has_exec(s)) {
                r = unit_add_exec_dependencies(u, &s->exec_context);
                if (r < 0)
                        return r;
        }

        r = unit_set_default_slice(u);
        if (r < 0)
                return r;

        r = socket_add_default_dependencies(s);
        if (r < 0)
                return r;

        return 0;
}

static const char *socket_find_symlink_target(Socket *s) {
        const char *found = NULL;
        SocketPort *p;

        LIST_FOREACH(port, p, s->ports) {
                const char *f = NULL;

                switch (p->type) {

                case SOCKET_FIFO:
                        f = p->path;
                        break;

                case SOCKET_SOCKET:
                        f = socket_address_get_path(&p->address);
                        break;

                default:
                        break;
                }

                if (f) {
                        if (found)
                                return NULL;

                        found = f;
                }
        }

        return found;
}

static int socket_verify(Socket *s) {
        assert(s);

        if (UNIT(s)->load_state != UNIT_LOADED)
                return 0;

        if (!s->ports) {
                log_unit_error(UNIT(s), "Unit has no Listen setting (ListenStream=, ListenDatagram=, ListenFIFO=, ...). Refusing.");
                return -ENOEXEC;
        }

        if (s->accept && have_non_accept_socket(s)) {
                log_unit_error(UNIT(s), "Unit configured for accepting sockets, but sockets are non-accepting. Refusing.");
                return -ENOEXEC;
        }

        if (s->accept && s->max_connections <= 0) {
                log_unit_error(UNIT(s), "MaxConnection= setting too small. Refusing.");
                return -ENOEXEC;
        }

        if (s->accept && UNIT_DEREF(s->service)) {
                log_unit_error(UNIT(s), "Explicit service configuration for accepting socket units not supported. Refusing.");
                return -ENOEXEC;
        }

        if (s->exec_context.pam_name && s->kill_context.kill_mode != KILL_CONTROL_GROUP) {
                log_unit_error(UNIT(s), "Unit has PAM enabled. Kill mode must be set to 'control-group'. Refusing.");
                return -ENOEXEC;
        }

        if (!strv_isempty(s->symlinks) && !socket_find_symlink_target(s)) {
                log_unit_error(UNIT(s), "Unit has symlinks set but none or more than one node in the file system. Refusing.");
                return -ENOEXEC;
        }

        return 0;
}

static void peer_address_hash_func(const SocketPeer *s, struct siphash *state) {
        assert(s);

        if (s->peer.sa.sa_family == AF_INET)
                siphash24_compress(&s->peer.in.sin_addr, sizeof(s->peer.in.sin_addr), state);
        else if (s->peer.sa.sa_family == AF_INET6)
                siphash24_compress(&s->peer.in6.sin6_addr, sizeof(s->peer.in6.sin6_addr), state);
        else if (s->peer.sa.sa_family == AF_VSOCK)
                siphash24_compress(&s->peer.vm.svm_cid, sizeof(s->peer.vm.svm_cid), state);
        else
                assert_not_reached("Unknown address family.");
}

static int peer_address_compare_func(const SocketPeer *x, const SocketPeer *y) {
        int r;

        r = CMP(x->peer.sa.sa_family, y->peer.sa.sa_family);
        if (r != 0)
                return r;

        switch(x->peer.sa.sa_family) {
        case AF_INET:
                return memcmp(&x->peer.in.sin_addr, &y->peer.in.sin_addr, sizeof(x->peer.in.sin_addr));
        case AF_INET6:
                return memcmp(&x->peer.in6.sin6_addr, &y->peer.in6.sin6_addr, sizeof(x->peer.in6.sin6_addr));
        case AF_VSOCK:
                return CMP(x->peer.vm.svm_cid, y->peer.vm.svm_cid);
        }
        assert_not_reached("Black sheep in the family!");
}

DEFINE_PRIVATE_HASH_OPS(peer_address_hash_ops, SocketPeer, peer_address_hash_func, peer_address_compare_func);

static int socket_load(Unit *u) {
        Socket *s = SOCKET(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        r = set_ensure_allocated(&s->peers_by_address, &peer_address_hash_ops);
        if (r < 0)
                return r;

        r = unit_load_fragment_and_dropin(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_LOADED) {
                /* This is a new unit? Then let's add in some extras */
                r = socket_add_extras(s);
                if (r < 0)
                        return r;
        }

        return socket_verify(s);
}

static SocketPeer *socket_peer_new(void) {
        SocketPeer *p;

        p = new0(SocketPeer, 1);
        if (!p)
                return NULL;

        p->n_ref = 1;

        return p;
}

static SocketPeer *socket_peer_free(SocketPeer *p) {
        assert(p);

        if (p->socket)
                set_remove(p->socket->peers_by_address, p);

        return mfree(p);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(SocketPeer, socket_peer, socket_peer_free);

int socket_acquire_peer(Socket *s, int fd, SocketPeer **p) {
        _cleanup_(socket_peer_unrefp) SocketPeer *remote = NULL;
        SocketPeer sa = {}, *i;
        socklen_t salen = sizeof(sa.peer);
        int r;

        assert(fd >= 0);
        assert(s);

        r = getpeername(fd, &sa.peer.sa, &salen);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), errno, "getpeername failed: %m");

        if (!IN_SET(sa.peer.sa.sa_family, AF_INET, AF_INET6, AF_VSOCK)) {
                *p = NULL;
                return 0;
        }

        i = set_get(s->peers_by_address, &sa);
        if (i) {
                *p = socket_peer_ref(i);
                return 1;
        }

        remote = socket_peer_new();
        if (!remote)
                return log_oom();

        remote->peer = sa.peer;
        remote->peer_salen = salen;

        r = set_put(s->peers_by_address, remote);
        if (r < 0)
                return r;

        remote->socket = s;

        *p = TAKE_PTR(remote);

        return 1;
}

_const_ static const char* listen_lookup(int family, int type) {

        if (family == AF_NETLINK)
                return "ListenNetlink";

        if (type == SOCK_STREAM)
                return "ListenStream";
        else if (type == SOCK_DGRAM)
                return "ListenDatagram";
        else if (type == SOCK_SEQPACKET)
                return "ListenSequentialPacket";

        assert_not_reached("Unknown socket type");
        return NULL;
}

static void socket_dump(Unit *u, FILE *f, const char *prefix) {
        char time_string[FORMAT_TIMESPAN_MAX];
        SocketExecCommand c;
        Socket *s = SOCKET(u);
        SocketPort *p;
        const char *prefix2, *str;

        assert(s);
        assert(f);

        prefix = strempty(prefix);
        prefix2 = strjoina(prefix, "\t");

        fprintf(f,
                "%sSocket State: %s\n"
                "%sResult: %s\n"
                "%sClean Result: %s\n"
                "%sBindIPv6Only: %s\n"
                "%sBacklog: %u\n"
                "%sSocketMode: %04o\n"
                "%sDirectoryMode: %04o\n"
                "%sKeepAlive: %s\n"
                "%sNoDelay: %s\n"
                "%sFreeBind: %s\n"
                "%sTransparent: %s\n"
                "%sBroadcast: %s\n"
                "%sPassCredentials: %s\n"
                "%sPassSecurity: %s\n"
                "%sTCPCongestion: %s\n"
                "%sRemoveOnStop: %s\n"
                "%sWritable: %s\n"
                "%sFileDescriptorName: %s\n"
                "%sSELinuxContextFromNet: %s\n",
                prefix, socket_state_to_string(s->state),
                prefix, socket_result_to_string(s->result),
                prefix, socket_result_to_string(s->clean_result),
                prefix, socket_address_bind_ipv6_only_to_string(s->bind_ipv6_only),
                prefix, s->backlog,
                prefix, s->socket_mode,
                prefix, s->directory_mode,
                prefix, yes_no(s->keep_alive),
                prefix, yes_no(s->no_delay),
                prefix, yes_no(s->free_bind),
                prefix, yes_no(s->transparent),
                prefix, yes_no(s->broadcast),
                prefix, yes_no(s->pass_cred),
                prefix, yes_no(s->pass_sec),
                prefix, strna(s->tcp_congestion),
                prefix, yes_no(s->remove_on_stop),
                prefix, yes_no(s->writable),
                prefix, socket_fdname(s),
                prefix, yes_no(s->selinux_context_from_net));

        if (s->control_pid > 0)
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, s->control_pid);

        if (s->bind_to_device)
                fprintf(f,
                        "%sBindToDevice: %s\n",
                        prefix, s->bind_to_device);

        if (s->accept)
                fprintf(f,
                        "%sAccepted: %u\n"
                        "%sNConnections: %u\n"
                        "%sMaxConnections: %u\n"
                        "%sMaxConnectionsPerSource: %u\n",
                        prefix, s->n_accepted,
                        prefix, s->n_connections,
                        prefix, s->max_connections,
                        prefix, s->max_connections_per_source);

        if (s->priority >= 0)
                fprintf(f,
                        "%sPriority: %i\n",
                        prefix, s->priority);

        if (s->receive_buffer > 0)
                fprintf(f,
                        "%sReceiveBuffer: %zu\n",
                        prefix, s->receive_buffer);

        if (s->send_buffer > 0)
                fprintf(f,
                        "%sSendBuffer: %zu\n",
                        prefix, s->send_buffer);

        if (s->ip_tos >= 0)
                fprintf(f,
                        "%sIPTOS: %i\n",
                        prefix, s->ip_tos);

        if (s->ip_ttl >= 0)
                fprintf(f,
                        "%sIPTTL: %i\n",
                        prefix, s->ip_ttl);

        if (s->pipe_size > 0)
                fprintf(f,
                        "%sPipeSize: %zu\n",
                        prefix, s->pipe_size);

        if (s->mark >= 0)
                fprintf(f,
                        "%sMark: %i\n",
                        prefix, s->mark);

        if (s->mq_maxmsg > 0)
                fprintf(f,
                        "%sMessageQueueMaxMessages: %li\n",
                        prefix, s->mq_maxmsg);

        if (s->mq_msgsize > 0)
                fprintf(f,
                        "%sMessageQueueMessageSize: %li\n",
                        prefix, s->mq_msgsize);

        if (s->reuse_port)
                fprintf(f,
                        "%sReusePort: %s\n",
                         prefix, yes_no(s->reuse_port));

        if (s->smack)
                fprintf(f,
                        "%sSmackLabel: %s\n",
                        prefix, s->smack);

        if (s->smack_ip_in)
                fprintf(f,
                        "%sSmackLabelIPIn: %s\n",
                        prefix, s->smack_ip_in);

        if (s->smack_ip_out)
                fprintf(f,
                        "%sSmackLabelIPOut: %s\n",
                        prefix, s->smack_ip_out);

        if (!isempty(s->user) || !isempty(s->group))
                fprintf(f,
                        "%sSocketUser: %s\n"
                        "%sSocketGroup: %s\n",
                        prefix, strna(s->user),
                        prefix, strna(s->group));

        if (s->keep_alive_time > 0)
                fprintf(f,
                        "%sKeepAliveTimeSec: %s\n",
                        prefix, format_timespan(time_string, FORMAT_TIMESPAN_MAX, s->keep_alive_time, USEC_PER_SEC));

        if (s->keep_alive_interval > 0)
                fprintf(f,
                        "%sKeepAliveIntervalSec: %s\n",
                        prefix, format_timespan(time_string, FORMAT_TIMESPAN_MAX, s->keep_alive_interval, USEC_PER_SEC));

        if (s->keep_alive_cnt > 0)
                fprintf(f,
                        "%sKeepAliveProbes: %u\n",
                        prefix, s->keep_alive_cnt);

        if (s->defer_accept > 0)
                fprintf(f,
                        "%sDeferAcceptSec: %s\n",
                        prefix, format_timespan(time_string, FORMAT_TIMESPAN_MAX, s->defer_accept, USEC_PER_SEC));

        LIST_FOREACH(port, p, s->ports) {

                switch (p->type) {
                case SOCKET_SOCKET: {
                        _cleanup_free_ char *k = NULL;
                        const char *t;
                        int r;

                        r = socket_address_print(&p->address, &k);
                        if (r < 0)
                                t = strerror_safe(r);
                        else
                                t = k;

                        fprintf(f, "%s%s: %s\n", prefix, listen_lookup(socket_address_family(&p->address), p->address.type), t);
                        break;
                }
                case SOCKET_SPECIAL:
                        fprintf(f, "%sListenSpecial: %s\n", prefix, p->path);
                        break;
                case SOCKET_USB_FUNCTION:
                        fprintf(f, "%sListenUSBFunction: %s\n", prefix, p->path);
                        break;
                case SOCKET_MQUEUE:
                        fprintf(f, "%sListenMessageQueue: %s\n", prefix, p->path);
                        break;
                default:
                        fprintf(f, "%sListenFIFO: %s\n", prefix, p->path);
                }
        }

        fprintf(f,
                "%sTriggerLimitIntervalSec: %s\n"
                "%sTriggerLimitBurst: %u\n",
                prefix, format_timespan(time_string, FORMAT_TIMESPAN_MAX, s->trigger_limit.interval, USEC_PER_SEC),
                prefix, s->trigger_limit.burst);

        str = ip_protocol_to_name(s->socket_protocol);
        if (str)
                fprintf(f, "%sSocketProtocol: %s\n", prefix, str);

        if (!strv_isempty(s->symlinks)) {
                char **q;

                fprintf(f, "%sSymlinks:", prefix);
                STRV_FOREACH(q, s->symlinks)
                        fprintf(f, " %s", *q);

                fprintf(f, "\n");
        }

        fprintf(f,
                "%sTimeoutSec: %s\n",
                prefix, format_timespan(time_string, FORMAT_TIMESPAN_MAX, s->timeout_usec, USEC_PER_SEC));

        exec_context_dump(&s->exec_context, f, prefix);
        kill_context_dump(&s->kill_context, f, prefix);

        for (c = 0; c < _SOCKET_EXEC_COMMAND_MAX; c++) {
                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s-> %s:\n",
                        prefix, socket_exec_command_to_string(c));

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

        cgroup_context_dump(&s->cgroup_context, f, prefix);
}

static int instance_from_socket(int fd, unsigned nr, char **instance) {
        socklen_t l;
        char *r;
        union sockaddr_union local, remote;

        assert(fd >= 0);
        assert(instance);

        l = sizeof(local);
        if (getsockname(fd, &local.sa, &l) < 0)
                return -errno;

        l = sizeof(remote);
        if (getpeername(fd, &remote.sa, &l) < 0)
                return -errno;

        switch (local.sa.sa_family) {

        case AF_INET: {
                uint32_t
                        a = be32toh(local.in.sin_addr.s_addr),
                        b = be32toh(remote.in.sin_addr.s_addr);

                if (asprintf(&r,
                             "%u-%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
                             nr,
                             a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                             be16toh(local.in.sin_port),
                             b >> 24, (b >> 16) & 0xFF, (b >> 8) & 0xFF, b & 0xFF,
                             be16toh(remote.in.sin_port)) < 0)
                        return -ENOMEM;

                break;
        }

        case AF_INET6: {
                static const unsigned char ipv4_prefix[] = {
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
                };

                if (memcmp(&local.in6.sin6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0 &&
                    memcmp(&remote.in6.sin6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0) {
                        const uint8_t
                                *a = local.in6.sin6_addr.s6_addr+12,
                                *b = remote.in6.sin6_addr.s6_addr+12;

                        if (asprintf(&r,
                                     "%u-%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
                                     nr,
                                     a[0], a[1], a[2], a[3],
                                     be16toh(local.in6.sin6_port),
                                     b[0], b[1], b[2], b[3],
                                     be16toh(remote.in6.sin6_port)) < 0)
                                return -ENOMEM;
                } else {
                        char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];

                        if (asprintf(&r,
                                     "%u-%s:%u-%s:%u",
                                     nr,
                                     inet_ntop(AF_INET6, &local.in6.sin6_addr, a, sizeof(a)),
                                     be16toh(local.in6.sin6_port),
                                     inet_ntop(AF_INET6, &remote.in6.sin6_addr, b, sizeof(b)),
                                     be16toh(remote.in6.sin6_port)) < 0)
                                return -ENOMEM;
                }

                break;
        }

        case AF_UNIX: {
                struct ucred ucred;
                int k;

                k = getpeercred(fd, &ucred);
                if (k >= 0) {
                        if (asprintf(&r,
                                     "%u-"PID_FMT"-"UID_FMT,
                                     nr, ucred.pid, ucred.uid) < 0)
                                return -ENOMEM;
                } else if (k == -ENODATA) {
                        /* This handles the case where somebody is
                         * connecting from another pid/uid namespace
                         * (e.g. from outside of our container). */
                        if (asprintf(&r,
                                     "%u-unknown",
                                     nr) < 0)
                                return -ENOMEM;
                } else
                        return k;

                break;
        }

        case AF_VSOCK:
                if (asprintf(&r,
                             "%u-%u:%u-%u:%u",
                             nr,
                             local.vm.svm_cid, local.vm.svm_port,
                             remote.vm.svm_cid, remote.vm.svm_port) < 0)
                        return -ENOMEM;

                break;

        default:
                assert_not_reached("Unhandled socket type.");
        }

        *instance = r;
        return 0;
}

static void socket_close_fds(Socket *s) {
        SocketPort *p;
        char **i;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                bool was_open;

                was_open = p->fd >= 0;

                p->event_source = sd_event_source_unref(p->event_source);
                p->fd = safe_close(p->fd);
                socket_cleanup_fd_list(p);

                /* One little note: we should normally not delete any sockets in the file system here! After all some
                 * other process we spawned might still have a reference of this fd and wants to continue to use
                 * it. Therefore we normally delete sockets in the file system before we create a new one, not after we
                 * stopped using one! That all said, if the user explicitly requested this, we'll delete them here
                 * anyway, but only then. */

                if (!was_open || !s->remove_on_stop)
                        continue;

                switch (p->type) {

                case SOCKET_FIFO:
                        (void) unlink(p->path);
                        break;

                case SOCKET_MQUEUE:
                        (void) mq_unlink(p->path);
                        break;

                case SOCKET_SOCKET:
                        (void) socket_address_unlink(&p->address);
                        break;

                default:
                        break;
                }
        }

        if (s->remove_on_stop)
                STRV_FOREACH(i, s->symlinks)
                        (void) unlink(*i);
}

static void socket_apply_socket_options(Socket *s, int fd) {
        int r;

        assert(s);
        assert(fd >= 0);

        if (s->keep_alive) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, true);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "SO_KEEPALIVE failed: %m");
        }

        if (s->keep_alive_time > 0) {
                r = setsockopt_int(fd, SOL_TCP, TCP_KEEPIDLE, s->keep_alive_time / USEC_PER_SEC);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "TCP_KEEPIDLE failed: %m");
        }

        if (s->keep_alive_interval > 0) {
                r = setsockopt_int(fd, SOL_TCP, TCP_KEEPINTVL, s->keep_alive_interval / USEC_PER_SEC);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "TCP_KEEPINTVL failed: %m");
        }

        if (s->keep_alive_cnt > 0) {
                r = setsockopt_int(fd, SOL_TCP, TCP_KEEPCNT, s->keep_alive_cnt);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "TCP_KEEPCNT failed: %m");
        }

        if (s->defer_accept > 0) {
                r = setsockopt_int(fd, SOL_TCP, TCP_DEFER_ACCEPT, s->defer_accept / USEC_PER_SEC);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "TCP_DEFER_ACCEPT failed: %m");
        }

        if (s->no_delay) {
                if (s->socket_protocol == IPPROTO_SCTP) {
                        r = setsockopt_int(fd, SOL_SCTP, SCTP_NODELAY, true);
                        if (r < 0)
                                log_unit_warning_errno(UNIT(s), r, "SCTP_NODELAY failed: %m");
                } else {
                        r = setsockopt_int(fd, SOL_TCP, TCP_NODELAY, true);
                        if (r < 0)
                                log_unit_warning_errno(UNIT(s), r, "TCP_NODELAY failed: %m");
                }
        }

        if (s->broadcast) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_BROADCAST, true);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "SO_BROADCAST failed: %m");
        }

        if (s->pass_cred) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "SO_PASSCRED failed: %m");
        }

        if (s->pass_sec) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSSEC, true);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "SO_PASSSEC failed: %m");
        }

        if (s->priority >= 0) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, s->priority);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "SO_PRIORITY failed: %m");
        }

        if (s->receive_buffer > 0) {
                /* We first try with SO_RCVBUFFORCE, in case we have the perms for that */
                if (setsockopt_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, s->receive_buffer) < 0) {
                        r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, s->receive_buffer);
                        if (r < 0)
                                log_unit_warning_errno(UNIT(s), r, "SO_RCVBUF failed: %m");
                }
        }

        if (s->send_buffer > 0) {
                if (setsockopt_int(fd, SOL_SOCKET, SO_SNDBUFFORCE, s->send_buffer) < 0) {
                        r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUF, s->send_buffer);
                        if (r < 0)
                                log_unit_warning_errno(UNIT(s), r, "SO_SNDBUF failed: %m");
                }
        }

        if (s->mark >= 0) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_MARK, s->mark);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "SO_MARK failed: %m");
        }

        if (s->ip_tos >= 0) {
                r = setsockopt_int(fd, IPPROTO_IP, IP_TOS, s->ip_tos);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "IP_TOS failed: %m");
        }

        if (s->ip_ttl >= 0) {
                int x;

                r = setsockopt_int(fd, IPPROTO_IP, IP_TTL, s->ip_ttl);

                if (socket_ipv6_is_supported())
                        x = setsockopt_int(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, s->ip_ttl);
                else
                        x = -EAFNOSUPPORT;

                if (r < 0 && x < 0)
                        log_unit_warning_errno(UNIT(s), r, "IP_TTL/IPV6_UNICAST_HOPS failed: %m");
        }

        if (s->tcp_congestion)
                if (setsockopt(fd, SOL_TCP, TCP_CONGESTION, s->tcp_congestion, strlen(s->tcp_congestion)+1) < 0)
                        log_unit_warning_errno(UNIT(s), errno, "TCP_CONGESTION failed: %m");

        if (s->smack_ip_in) {
                r = mac_smack_apply_fd(fd, SMACK_ATTR_IPIN, s->smack_ip_in);
                if (r < 0)
                        log_unit_error_errno(UNIT(s), r, "mac_smack_apply_ip_in_fd: %m");
        }

        if (s->smack_ip_out) {
                r = mac_smack_apply_fd(fd, SMACK_ATTR_IPOUT, s->smack_ip_out);
                if (r < 0)
                        log_unit_error_errno(UNIT(s), r, "mac_smack_apply_ip_out_fd: %m");
        }
}

static void socket_apply_fifo_options(Socket *s, int fd) {
        int r;

        assert(s);
        assert(fd >= 0);

        if (s->pipe_size > 0)
                if (fcntl(fd, F_SETPIPE_SZ, s->pipe_size) < 0)
                        log_unit_warning_errno(UNIT(s), errno, "Setting pipe size failed, ignoring: %m");

        if (s->smack) {
                r = mac_smack_apply_fd(fd, SMACK_ATTR_ACCESS, s->smack);
                if (r < 0)
                        log_unit_error_errno(UNIT(s), r, "SMACK relabelling failed, ignoring: %m");
        }
}

static int fifo_address_create(
                const char *path,
                mode_t directory_mode,
                mode_t socket_mode) {

        _cleanup_close_ int fd = -1;
        mode_t old_mask;
        struct stat st;
        int r;

        assert(path);

        (void) mkdir_parents_label(path, directory_mode);

        r = mac_selinux_create_file_prepare(path, S_IFIFO);
        if (r < 0)
                return r;

        /* Enforce the right access mode for the fifo */
        old_mask = umask(~socket_mode);

        /* Include the original umask in our mask */
        (void) umask(~socket_mode | old_mask);

        r = mkfifo(path, socket_mode);
        (void) umask(old_mask);

        if (r < 0 && errno != EEXIST) {
                r = -errno;
                goto fail;
        }

        fd = open(path, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW);
        if (fd < 0) {
                r = -errno;
                goto fail;
        }

        mac_selinux_create_file_clear();

        if (fstat(fd, &st) < 0) {
                r = -errno;
                goto fail;
        }

        if (!S_ISFIFO(st.st_mode) ||
            (st.st_mode & 0777) != (socket_mode & ~old_mask) ||
            st.st_uid != getuid() ||
            st.st_gid != getgid()) {
                r = -EEXIST;
                goto fail;
        }

        return TAKE_FD(fd);

fail:
        mac_selinux_create_file_clear();
        return r;
}

static int special_address_create(const char *path, bool writable) {
        _cleanup_close_ int fd = -1;
        struct stat st;

        assert(path);

        fd = open(path, (writable ? O_RDWR : O_RDONLY)|O_CLOEXEC|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Check whether this is a /proc, /sys or /dev file or char device */
        if (!S_ISREG(st.st_mode) && !S_ISCHR(st.st_mode))
                return -EEXIST;

        return TAKE_FD(fd);
}

static int usbffs_address_create(const char *path) {
        _cleanup_close_ int fd = -1;
        struct stat st;

        assert(path);

        fd = open(path, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Check whether this is a regular file (ffs endpoint) */
        if (!S_ISREG(st.st_mode))
                return -EEXIST;

        return TAKE_FD(fd);
}

static int mq_address_create(
                const char *path,
                mode_t mq_mode,
                long maxmsg,
                long msgsize) {

        _cleanup_close_ int fd = -1;
        struct stat st;
        mode_t old_mask;
        struct mq_attr _attr, *attr = NULL;

        assert(path);

        if (maxmsg > 0 && msgsize > 0) {
                _attr = (struct mq_attr) {
                        .mq_flags = O_NONBLOCK,
                        .mq_maxmsg = maxmsg,
                        .mq_msgsize = msgsize,
                };
                attr = &_attr;
        }

        /* Enforce the right access mode for the mq */
        old_mask = umask(~mq_mode);

        /* Include the original umask in our mask */
        (void) umask(~mq_mode | old_mask);
        fd = mq_open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_CREAT, mq_mode, attr);
        (void) umask(old_mask);

        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if ((st.st_mode & 0777) != (mq_mode & ~old_mask) ||
            st.st_uid != getuid() ||
            st.st_gid != getgid())
                return -EEXIST;

        return TAKE_FD(fd);
}

static int socket_symlink(Socket *s) {
        const char *p;
        char **i;
        int r;

        assert(s);

        p = socket_find_symlink_target(s);
        if (!p)
                return 0;

        STRV_FOREACH(i, s->symlinks) {
                (void) mkdir_parents_label(*i, s->directory_mode);

                r = symlink_idempotent(p, *i, false);

                if (r == -EEXIST && s->remove_on_stop) {
                        /* If there's already something where we want to create the symlink, and the destructive
                         * RemoveOnStop= mode is set, then we might as well try to remove what already exists and try
                         * again. */

                        if (unlink(*i) >= 0)
                                r = symlink_idempotent(p, *i, false);
                }

                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "Failed to create symlink %s → %s, ignoring: %m", p, *i);
        }

        return 0;
}

static int usbffs_write_descs(int fd, Service *s) {
        int r;

        if (!s->usb_function_descriptors || !s->usb_function_strings)
                return -EINVAL;

        r = copy_file_fd(s->usb_function_descriptors, fd, 0);
        if (r < 0)
                return r;

        return copy_file_fd(s->usb_function_strings, fd, 0);
}

static int usbffs_select_ep(const struct dirent *d) {
        return d->d_name[0] != '.' && !streq(d->d_name, "ep0");
}

static int usbffs_dispatch_eps(SocketPort *p) {
        _cleanup_free_ struct dirent **ent = NULL;
        size_t n, k, i;
        int r;

        r = scandir(p->path, &ent, usbffs_select_ep, alphasort);
        if (r < 0)
                return -errno;

        n = (size_t) r;
        p->auxiliary_fds = new(int, n);
        if (!p->auxiliary_fds) {
                r = -ENOMEM;
                goto clear;
        }

        p->n_auxiliary_fds = n;

        k = 0;
        for (i = 0; i < n; ++i) {
                _cleanup_free_ char *ep = NULL;

                ep = path_make_absolute(ent[i]->d_name, p->path);
                if (!ep) {
                        r = -ENOMEM;
                        goto fail;
                }

                path_simplify(ep, false);

                r = usbffs_address_create(ep);
                if (r < 0)
                        goto fail;

                p->auxiliary_fds[k++] = r;
        }

        r = 0;
        goto clear;

fail:
        close_many(p->auxiliary_fds, k);
        p->auxiliary_fds = mfree(p->auxiliary_fds);
        p->n_auxiliary_fds = 0;

clear:
        for (i = 0; i < n; ++i)
                free(ent[i]);

        return r;
}

static int socket_determine_selinux_label(Socket *s, char **ret) {
        Service *service;
        ExecCommand *c;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(s);
        assert(ret);

        if (s->selinux_context_from_net) {
                /* If this is requested, get label from the network label */

                r = mac_selinux_get_our_label(ret);
                if (r == -EOPNOTSUPP)
                        goto no_label;

        } else {
                /* Otherwise, get it from the executable we are about to start */
                r = socket_instantiate_service(s);
                if (r < 0)
                        return r;

                if (!UNIT_ISSET(s->service))
                        goto no_label;

                service = SERVICE(UNIT_DEREF(s->service));
                c = service->exec_command[SERVICE_EXEC_START];
                if (!c)
                        goto no_label;

                r = chase_symlinks(c->path, service->exec_context.root_directory, CHASE_PREFIX_ROOT, &path);
                if (r < 0)
                        goto no_label;

                r = mac_selinux_get_create_label_from_exe(path, ret);
                if (IN_SET(r, -EPERM, -EOPNOTSUPP))
                        goto no_label;
        }

        return r;

no_label:
        *ret = NULL;
        return 0;
}

static int socket_address_listen_do(
                Socket *s,
                const SocketAddress *address,
                const char *label) {

        assert(s);
        assert(address);

        return socket_address_listen(
                        address,
                        SOCK_CLOEXEC|SOCK_NONBLOCK,
                        s->backlog,
                        s->bind_ipv6_only,
                        s->bind_to_device,
                        s->reuse_port,
                        s->free_bind,
                        s->transparent,
                        s->directory_mode,
                        s->socket_mode,
                        label);
}

#define log_address_error_errno(u, address, error, fmt)          \
        ({                                                       \
                _cleanup_free_ char *_t = NULL;                  \
                                                                 \
                (void) socket_address_print(address, &_t);       \
                log_unit_error_errno(u, error, fmt, strna(_t));  \
        })

static int fork_needed(const SocketAddress *address, const ExecContext *context) {
        int r;

        assert(address);
        assert(context);

        /* Check if we need to do the cgroup or netns stuff. If not we can do things much simpler. */

        if (IN_SET(address->sockaddr.sa.sa_family, AF_INET, AF_INET6)) {
                r = bpf_firewall_supported();
                if (r < 0)
                        return r;
                if (r != BPF_FIREWALL_UNSUPPORTED) /* If BPF firewalling isn't supported anyway — there's no point in this forking complexity */
                        return true;
        }

        return context->private_network || context->network_namespace_path;
}

static int socket_address_listen_in_cgroup(
                Socket *s,
                const SocketAddress *address,
                const char *label) {

        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        int fd, r;
        pid_t pid;

        assert(s);
        assert(address);

        /* This is a wrapper around socket_address_listen(), that forks off a helper process inside the
         * socket's cgroup and network namespace in which the socket is actually created. This way we ensure
         * the socket is actually properly attached to the unit's cgroup for the purpose of BPF filtering and
         * such. */

        r = fork_needed(address, &s->exec_context);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Shortcut things... */
                fd = socket_address_listen_do(s, address, label);
                if (fd < 0)
                        return log_address_error_errno(UNIT(s), address, fd, "Failed to create listening socket (%s): %m");

                return fd;
        }

        r = unit_setup_exec_runtime(UNIT(s));
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed acquire runtime: %m");

        if (s->exec_context.network_namespace_path &&
            s->exec_runtime &&
            s->exec_runtime->netns_storage_socket[0] >= 0) {
                r = open_netns_path(s->exec_runtime->netns_storage_socket, s->exec_context.network_namespace_path);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to open network namespace path %s: %m", s->exec_context.network_namespace_path);
        }

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) < 0)
                return log_unit_error_errno(UNIT(s), errno, "Failed to create communication channel: %m");

        r = unit_fork_helper_process(UNIT(s), "(sd-listen)", &pid);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to fork off listener stub process: %m");
        if (r == 0) {
                /* Child */

                pair[0] = safe_close(pair[0]);

                if ((s->exec_context.private_network || s->exec_context.network_namespace_path) &&
                    s->exec_runtime &&
                    s->exec_runtime->netns_storage_socket[0] >= 0) {

                        if (ns_type_supported(NAMESPACE_NET)) {
                                r = setup_netns(s->exec_runtime->netns_storage_socket);
                                if (r < 0) {
                                        log_unit_error_errno(UNIT(s), r, "Failed to join network namespace: %m");
                                        _exit(EXIT_NETWORK);
                                }
                        } else if (s->exec_context.network_namespace_path) {
                                log_unit_error(UNIT(s), "Network namespace path configured but network namespaces not supported.");
                                _exit(EXIT_NETWORK);
                        } else
                                log_unit_warning(UNIT(s), "PrivateNetwork=yes is configured, but the kernel does not support network namespaces, ignoring.");
                }

                fd = socket_address_listen_do(s, address, label);
                if (fd < 0) {
                        log_address_error_errno(UNIT(s), address, fd, "Failed to create listening socket (%s): %m");
                        _exit(EXIT_FAILURE);
                }

                r = send_one_fd(pair[1], fd, 0);
                if (r < 0) {
                        log_address_error_errno(UNIT(s), address, r, "Failed to send listening socket (%s) to parent: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);
        fd = receive_one_fd(pair[0], 0);

        /* We synchronously wait for the helper, as it shouldn't be slow */
        r = wait_for_terminate_and_check("(sd-listen)", pid, WAIT_LOG_ABNORMAL);
        if (r < 0) {
                safe_close(fd);
                return r;
        }

        if (fd < 0)
                return log_address_error_errno(UNIT(s), address, fd, "Failed to receive listening socket (%s): %m");

        return fd;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Socket *, socket_close_fds);

static int socket_open_fds(Socket *_s) {
        _cleanup_(socket_close_fdsp) Socket *s = _s;
        _cleanup_(mac_selinux_freep) char *label = NULL;
        bool know_label = false;
        SocketPort *p;
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {

                if (p->fd >= 0)
                        continue;

                switch (p->type) {

                case SOCKET_SOCKET:

                        if (!know_label) {
                                /* Figure out label, if we don't it know yet. We do it once, for the first socket where
                                 * we need this and remember it for the rest. */

                                r = socket_determine_selinux_label(s, &label);
                                if (r < 0)
                                        return log_unit_error_errno(UNIT(s), r, "Failed to determine SELinux label: %m");

                                know_label = true;
                        }

                        /* Apply the socket protocol */
                        switch (p->address.type) {

                        case SOCK_STREAM:
                        case SOCK_SEQPACKET:
                                if (s->socket_protocol == IPPROTO_SCTP)
                                        p->address.protocol = s->socket_protocol;
                                break;

                        case SOCK_DGRAM:
                                if (s->socket_protocol == IPPROTO_UDPLITE)
                                        p->address.protocol = s->socket_protocol;
                                break;
                        }

                        p->fd = socket_address_listen_in_cgroup(s, &p->address, label);
                        if (p->fd < 0)
                                return p->fd;

                        socket_apply_socket_options(s, p->fd);
                        socket_symlink(s);
                        break;

                case SOCKET_SPECIAL:

                        p->fd = special_address_create(p->path, s->writable);
                        if (p->fd < 0)
                                return log_unit_error_errno(UNIT(s), p->fd, "Failed to open special file %s: %m", p->path);
                        break;

                case SOCKET_FIFO:

                        p->fd = fifo_address_create(
                                        p->path,
                                        s->directory_mode,
                                        s->socket_mode);
                        if (p->fd < 0)
                                return log_unit_error_errno(UNIT(s), p->fd, "Failed to open FIFO %s: %m", p->path);

                        socket_apply_fifo_options(s, p->fd);
                        socket_symlink(s);
                        break;

                case SOCKET_MQUEUE:

                        p->fd = mq_address_create(
                                        p->path,
                                        s->socket_mode,
                                        s->mq_maxmsg,
                                        s->mq_msgsize);
                        if (p->fd < 0)
                                return log_unit_error_errno(UNIT(s), p->fd, "Failed to open message queue %s: %m", p->path);
                        break;

                case SOCKET_USB_FUNCTION: {
                        _cleanup_free_ char *ep = NULL;

                        ep = path_make_absolute("ep0", p->path);

                        p->fd = usbffs_address_create(ep);
                        if (p->fd < 0)
                                return p->fd;

                        r = usbffs_write_descs(p->fd, SERVICE(UNIT_DEREF(s->service)));
                        if (r < 0)
                                return r;

                        r = usbffs_dispatch_eps(p);
                        if (r < 0)
                                return r;

                        break;
                }
                default:
                        assert_not_reached("Unknown port type");
                }
        }

        s = NULL;
        return 0;
}

static void socket_unwatch_fds(Socket *s) {
        SocketPort *p;
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                if (!p->event_source)
                        continue;

                r = sd_event_source_set_enabled(p->event_source, SD_EVENT_OFF);
                if (r < 0)
                        log_unit_debug_errno(UNIT(s), r, "Failed to disable event source: %m");
        }
}

static int socket_watch_fds(Socket *s) {
        SocketPort *p;
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                if (p->event_source) {
                        r = sd_event_source_set_enabled(p->event_source, SD_EVENT_ON);
                        if (r < 0)
                                goto fail;
                } else {
                        r = sd_event_add_io(UNIT(s)->manager->event, &p->event_source, p->fd, EPOLLIN, socket_dispatch_io, p);
                        if (r < 0)
                                goto fail;

                        (void) sd_event_source_set_description(p->event_source, "socket-port-io");
                }
        }

        return 0;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to watch listening fds: %m");
        socket_unwatch_fds(s);
        return r;
}

enum {
        SOCKET_OPEN_NONE,
        SOCKET_OPEN_SOME,
        SOCKET_OPEN_ALL,
};

static int socket_check_open(Socket *s) {
        bool have_open = false, have_closed = false;
        SocketPort *p;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        have_closed = true;
                else
                        have_open = true;

                if (have_open && have_closed)
                        return SOCKET_OPEN_SOME;
        }

        if (have_open)
                return SOCKET_OPEN_ALL;

        return SOCKET_OPEN_NONE;
}

static void socket_set_state(Socket *s, SocketState state) {
        SocketState old_state;
        assert(s);

        if (s->state != state)
                bus_unit_send_pending_change_signal(UNIT(s), false);

        old_state = s->state;
        s->state = state;

        if (!IN_SET(state,
                    SOCKET_START_PRE,
                    SOCKET_START_CHOWN,
                    SOCKET_START_POST,
                    SOCKET_STOP_PRE,
                    SOCKET_STOP_PRE_SIGTERM,
                    SOCKET_STOP_PRE_SIGKILL,
                    SOCKET_STOP_POST,
                    SOCKET_FINAL_SIGTERM,
                    SOCKET_FINAL_SIGKILL,
                    SOCKET_CLEANING)) {

                s->timer_event_source = sd_event_source_unref(s->timer_event_source);
                socket_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SOCKET_EXEC_COMMAND_INVALID;
        }

        if (state != SOCKET_LISTENING)
                socket_unwatch_fds(s);

        if (!IN_SET(state,
                    SOCKET_START_CHOWN,
                    SOCKET_START_POST,
                    SOCKET_LISTENING,
                    SOCKET_RUNNING,
                    SOCKET_STOP_PRE,
                    SOCKET_STOP_PRE_SIGTERM,
                    SOCKET_STOP_PRE_SIGKILL,
                    SOCKET_CLEANING))
                socket_close_fds(s);

        if (state != old_state)
                log_unit_debug(UNIT(s), "Changed %s -> %s", socket_state_to_string(old_state), socket_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state], 0);
}

static int socket_coldplug(Unit *u) {
        Socket *s = SOCKET(u);
        int r;

        assert(s);
        assert(s->state == SOCKET_DEAD);

        if (s->deserialized_state == s->state)
                return 0;

        if (s->control_pid > 0 &&
            pid_is_unwaited(s->control_pid) &&
            IN_SET(s->deserialized_state,
                   SOCKET_START_PRE,
                   SOCKET_START_CHOWN,
                   SOCKET_START_POST,
                   SOCKET_STOP_PRE,
                   SOCKET_STOP_PRE_SIGTERM,
                   SOCKET_STOP_PRE_SIGKILL,
                   SOCKET_STOP_POST,
                   SOCKET_FINAL_SIGTERM,
                   SOCKET_FINAL_SIGKILL,
                   SOCKET_CLEANING)) {

                r = unit_watch_pid(UNIT(s), s->control_pid, false);
                if (r < 0)
                        return r;

                r = socket_arm_timer(s, usec_add(u->state_change_timestamp.monotonic, s->timeout_usec));
                if (r < 0)
                        return r;
        }

        if (IN_SET(s->deserialized_state,
                   SOCKET_START_CHOWN,
                   SOCKET_START_POST,
                   SOCKET_LISTENING,
                   SOCKET_RUNNING)) {

                /* Originally, we used to simply reopen all sockets here that we didn't have file descriptors
                 * for. However, this is problematic, as we won't traverse through the SOCKET_START_CHOWN state for
                 * them, and thus the UID/GID wouldn't be right. Hence, instead simply check if we have all fds open,
                 * and if there's a mismatch, warn loudly. */

                r = socket_check_open(s);
                if (r == SOCKET_OPEN_NONE)
                        log_unit_warning(UNIT(s),
                                         "Socket unit configuration has changed while unit has been running, "
                                         "no open socket file descriptor left. "
                                         "The socket unit is not functional until restarted.");
                else if (r == SOCKET_OPEN_SOME)
                        log_unit_warning(UNIT(s),
                                         "Socket unit configuration has changed while unit has been running, "
                                         "and some socket file descriptors have not been opened yet. "
                                         "The socket unit is not fully functional until restarted.");
        }

        if (s->deserialized_state == SOCKET_LISTENING) {
                r = socket_watch_fds(s);
                if (r < 0)
                        return r;
        }

        if (!IN_SET(s->deserialized_state, SOCKET_DEAD, SOCKET_FAILED, SOCKET_CLEANING)) {
                (void) unit_setup_dynamic_creds(u);
                (void) unit_setup_exec_runtime(u);
        }

        socket_set_state(s, s->deserialized_state);
        return 0;
}

static int socket_spawn(Socket *s, ExecCommand *c, pid_t *_pid) {

        _cleanup_(exec_params_clear) ExecParameters exec_params = {
                .flags     = EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN,
                .stdin_fd  = -1,
                .stdout_fd = -1,
                .stderr_fd = -1,
                .exec_fd   = -1,
        };
        pid_t pid;
        int r;

        assert(s);
        assert(c);
        assert(_pid);

        r = unit_prepare_exec(UNIT(s));
        if (r < 0)
                return r;

        r = socket_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->timeout_usec));
        if (r < 0)
                return r;

        r = unit_set_exec_params(UNIT(s), &exec_params);
        if (r < 0)
                return r;

        r = exec_spawn(UNIT(s),
                       c,
                       &s->exec_context,
                       &exec_params,
                       s->exec_runtime,
                       &s->dynamic_creds,
                       &pid);
        if (r < 0)
                return r;

        r = unit_watch_pid(UNIT(s), pid, true);
        if (r < 0)
                return r;

        *_pid = pid;

        return 0;
}

static int socket_chown(Socket *s, pid_t *_pid) {
        pid_t pid;
        int r;

        r = socket_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->timeout_usec));
        if (r < 0)
                goto fail;

        /* We have to resolve the user names out-of-process, hence
         * let's fork here. It's messy, but well, what can we do? */

        r = unit_fork_helper_process(UNIT(s), "(sd-chown)", &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                uid_t uid = UID_INVALID;
                gid_t gid = GID_INVALID;
                SocketPort *p;

                /* Child */

                if (!isempty(s->user)) {
                        const char *user = s->user;

                        r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                        if (r < 0) {
                                log_unit_error_errno(UNIT(s), r, "Failed to resolve user %s: %m", user);
                                _exit(EXIT_USER);
                        }
                }

                if (!isempty(s->group)) {
                        const char *group = s->group;

                        r = get_group_creds(&group, &gid, 0);
                        if (r < 0) {
                                log_unit_error_errno(UNIT(s), r, "Failed to resolve group %s: %m", group);
                                _exit(EXIT_GROUP);
                        }
                }

                LIST_FOREACH(port, p, s->ports) {
                        const char *path = NULL;

                        if (p->type == SOCKET_SOCKET)
                                path = socket_address_get_path(&p->address);
                        else if (p->type == SOCKET_FIFO)
                                path = p->path;

                        if (!path)
                                continue;

                        if (chown(path, uid, gid) < 0) {
                                log_unit_error_errno(UNIT(s), errno, "Failed to chown(): %m");
                                _exit(EXIT_CHOWN);
                        }
                }

                _exit(EXIT_SUCCESS);
        }

        r = unit_watch_pid(UNIT(s), pid, true);
        if (r < 0)
                goto fail;

        *_pid = pid;
        return 0;

fail:
        s->timer_event_source = sd_event_source_unref(s->timer_event_source);
        return r;
}

static void socket_enter_dead(Socket *s, SocketResult f) {
        assert(s);

        if (s->result == SOCKET_SUCCESS)
                s->result = f;

        if (s->result == SOCKET_SUCCESS)
                unit_log_success(UNIT(s));
        else
                unit_log_failure(UNIT(s), socket_result_to_string(s->result));

        socket_set_state(s, s->result != SOCKET_SUCCESS ? SOCKET_FAILED : SOCKET_DEAD);

        s->exec_runtime = exec_runtime_unref(s->exec_runtime, true);

        unit_destroy_runtime_directory(UNIT(s), &s->exec_context);

        unit_unref_uid_gid(UNIT(s), true);

        dynamic_creds_destroy(&s->dynamic_creds);
}

static void socket_enter_signal(Socket *s, SocketState state, SocketResult f);

static void socket_enter_stop_post(Socket *s, SocketResult f) {
        int r;
        assert(s);

        if (s->result == SOCKET_SUCCESS)
                s->result = f;

        socket_unwatch_control_pid(s);
        s->control_command_id = SOCKET_EXEC_STOP_POST;
        s->control_command = s->exec_command[SOCKET_EXEC_STOP_POST];

        if (s->control_command) {
                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0)
                        goto fail;

                socket_set_state(s, SOCKET_STOP_POST);
        } else
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'stop-post' task: %m");
        socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_FAILURE_RESOURCES);
}

static void socket_enter_signal(Socket *s, SocketState state, SocketResult f) {
        int r;

        assert(s);

        if (s->result == SOCKET_SUCCESS)
                s->result = f;

        r = unit_kill_context(
                        UNIT(s),
                        &s->kill_context,
                        !IN_SET(state, SOCKET_STOP_PRE_SIGTERM, SOCKET_FINAL_SIGTERM) ?
                        KILL_KILL : KILL_TERMINATE,
                        -1,
                        s->control_pid,
                        false);
        if (r < 0)
                goto fail;

        if (r > 0) {
                r = socket_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->timeout_usec));
                if (r < 0)
                        goto fail;

                socket_set_state(s, state);
        } else if (state == SOCKET_STOP_PRE_SIGTERM)
                socket_enter_signal(s, SOCKET_STOP_PRE_SIGKILL, SOCKET_SUCCESS);
        else if (state == SOCKET_STOP_PRE_SIGKILL)
                socket_enter_stop_post(s, SOCKET_SUCCESS);
        else if (state == SOCKET_FINAL_SIGTERM)
                socket_enter_signal(s, SOCKET_FINAL_SIGKILL, SOCKET_SUCCESS);
        else
                socket_enter_dead(s, SOCKET_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");

        if (IN_SET(state, SOCKET_STOP_PRE_SIGTERM, SOCKET_STOP_PRE_SIGKILL))
                socket_enter_stop_post(s, SOCKET_FAILURE_RESOURCES);
        else
                socket_enter_dead(s, SOCKET_FAILURE_RESOURCES);
}

static void socket_enter_stop_pre(Socket *s, SocketResult f) {
        int r;
        assert(s);

        if (s->result == SOCKET_SUCCESS)
                s->result = f;

        socket_unwatch_control_pid(s);
        s->control_command_id = SOCKET_EXEC_STOP_PRE;
        s->control_command = s->exec_command[SOCKET_EXEC_STOP_PRE];

        if (s->control_command) {
                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0)
                        goto fail;

                socket_set_state(s, SOCKET_STOP_PRE);
        } else
                socket_enter_stop_post(s, SOCKET_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'stop-pre' task: %m");
        socket_enter_stop_post(s, SOCKET_FAILURE_RESOURCES);
}

static void socket_enter_listening(Socket *s) {
        int r;
        assert(s);

        r = socket_watch_fds(s);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to watch sockets: %m");
                goto fail;
        }

        socket_set_state(s, SOCKET_LISTENING);
        return;

fail:
        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
}

static void socket_enter_start_post(Socket *s) {
        int r;
        assert(s);

        socket_unwatch_control_pid(s);
        s->control_command_id = SOCKET_EXEC_START_POST;
        s->control_command = s->exec_command[SOCKET_EXEC_START_POST];

        if (s->control_command) {
                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to run 'start-post' task: %m");
                        goto fail;
                }

                socket_set_state(s, SOCKET_START_POST);
        } else
                socket_enter_listening(s);

        return;

fail:
        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
}

static void socket_enter_start_chown(Socket *s) {
        int r;

        assert(s);

        r = socket_open_fds(s);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to listen on sockets: %m");
                goto fail;
        }

        if (!isempty(s->user) || !isempty(s->group)) {

                socket_unwatch_control_pid(s);
                s->control_command_id = SOCKET_EXEC_START_CHOWN;
                s->control_command = NULL;

                r = socket_chown(s, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to fork 'start-chown' task: %m");
                        goto fail;
                }

                socket_set_state(s, SOCKET_START_CHOWN);
        } else
                socket_enter_start_post(s);

        return;

fail:
        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
}

static void socket_enter_start_pre(Socket *s) {
        int r;
        assert(s);

        socket_unwatch_control_pid(s);

        unit_warn_leftover_processes(UNIT(s));

        s->control_command_id = SOCKET_EXEC_START_PRE;
        s->control_command = s->exec_command[SOCKET_EXEC_START_PRE];

        if (s->control_command) {
                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to run 'start-pre' task: %m");
                        goto fail;
                }

                socket_set_state(s, SOCKET_START_PRE);
        } else
                socket_enter_start_chown(s);

        return;

fail:
        socket_enter_dead(s, SOCKET_FAILURE_RESOURCES);
}

static void flush_ports(Socket *s) {
        SocketPort *p;

        /* Flush all incoming traffic, regardless if actual bytes or new connections, so that this socket isn't busy
         * anymore */

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                (void) flush_accept(p->fd);
                (void) flush_fd(p->fd);
        }
}

static void socket_enter_running(Socket *s, int cfd) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        /* Note that this call takes possession of the connection fd passed. It either has to assign it somewhere or
         * close it. */

        assert(s);

        /* We don't take connections anymore if we are supposed to shut down anyway */
        if (unit_stop_pending(UNIT(s))) {

                log_unit_debug(UNIT(s), "Suppressing connection request since unit stop is scheduled.");

                if (cfd >= 0)
                        goto refuse;
                else
                        flush_ports(s);

                return;
        }

        if (!ratelimit_below(&s->trigger_limit)) {
                log_unit_warning(UNIT(s), "Trigger limit hit, refusing further activation.");
                socket_enter_stop_pre(s, SOCKET_FAILURE_TRIGGER_LIMIT_HIT);
                goto refuse;
        }

        if (cfd < 0) {
                bool pending = false;
                Unit *other;
                Iterator i;
                void *v;

                /* If there's already a start pending don't bother to
                 * do anything */
                HASHMAP_FOREACH_KEY(v, other, UNIT(s)->dependencies[UNIT_TRIGGERS], i)
                        if (unit_active_or_pending(other)) {
                                pending = true;
                                break;
                        }

                if (!pending) {
                        if (!UNIT_ISSET(s->service)) {
                                log_unit_error(UNIT(s), "Service to activate vanished, refusing activation.");
                                r = -ENOENT;
                                goto fail;
                        }

                        r = manager_add_job(UNIT(s)->manager, JOB_START, UNIT_DEREF(s->service), JOB_REPLACE, NULL, &error, NULL);
                        if (r < 0)
                                goto fail;
                }

                socket_set_state(s, SOCKET_RUNNING);
        } else {
                _cleanup_free_ char *prefix = NULL, *instance = NULL, *name = NULL;
                _cleanup_(socket_peer_unrefp) SocketPeer *p = NULL;
                Service *service;

                if (s->n_connections >= s->max_connections) {
                        log_unit_warning(UNIT(s), "Too many incoming connections (%u), dropping connection.",
                                         s->n_connections);
                        goto refuse;
                }

                if (s->max_connections_per_source > 0) {
                        r = socket_acquire_peer(s, cfd, &p);
                        if (r < 0) {
                                goto refuse;
                        } else if (r > 0 && p->n_ref > s->max_connections_per_source) {
                                _cleanup_free_ char *t = NULL;

                                (void) sockaddr_pretty(&p->peer.sa, p->peer_salen, true, false, &t);

                                log_unit_warning(UNIT(s),
                                                 "Too many incoming connections (%u) from source %s, dropping connection.",
                                                 p->n_ref, strnull(t));
                                goto refuse;
                        }
                }

                r = socket_instantiate_service(s);
                if (r < 0)
                        goto fail;

                r = instance_from_socket(cfd, s->n_accepted, &instance);
                if (r < 0) {
                        if (r != -ENOTCONN)
                                goto fail;

                        /* ENOTCONN is legitimate if TCP RST was received.
                         * This connection is over, but the socket unit lives on. */
                        log_unit_debug(UNIT(s), "Got ENOTCONN on incoming socket, assuming aborted connection attempt, ignoring.");
                        goto refuse;
                }

                r = unit_name_to_prefix(UNIT(s)->id, &prefix);
                if (r < 0)
                        goto fail;

                r = unit_name_build(prefix, instance, ".service", &name);
                if (r < 0)
                        goto fail;

                r = unit_add_name(UNIT_DEREF(s->service), name);
                if (r < 0)
                        goto fail;

                service = SERVICE(UNIT_DEREF(s->service));
                unit_ref_unset(&s->service);

                s->n_accepted++;
                unit_choose_id(UNIT(service), name);

                r = service_set_socket_fd(service, cfd, s, s->selinux_context_from_net);
                if (r < 0)
                        goto fail;

                cfd = -1; /* We passed ownership of the fd to the service now. Forget it here. */
                s->n_connections++;

                service->peer = TAKE_PTR(p); /* Pass ownership of the peer reference */

                r = manager_add_job(UNIT(s)->manager, JOB_START, UNIT(service), JOB_REPLACE, NULL, &error, NULL);
                if (r < 0) {
                        /* We failed to activate the new service, but it still exists. Let's make sure the service
                         * closes and forgets the connection fd again, immediately. */
                        service_close_socket_fd(service);
                        goto fail;
                }

                /* Notify clients about changed counters */
                unit_add_to_dbus_queue(UNIT(s));
        }

        return;

refuse:
        s->n_refused++;
        safe_close(cfd);
        return;

fail:
        log_unit_warning(UNIT(s), "Failed to queue service startup job (Maybe the service file is missing or not a %s unit?): %s",
                         cfd >= 0 ? "template" : "non-template",
                         bus_error_message(&error, r));

        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
        safe_close(cfd);
}

static void socket_run_next(Socket *s) {
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        socket_unwatch_control_pid(s);

        s->control_command = s->control_command->command_next;

        r = socket_spawn(s, s->control_command, &s->control_pid);
        if (r < 0)
                goto fail;

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run next task: %m");

        if (s->state == SOCKET_START_POST)
                socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
        else if (s->state == SOCKET_STOP_POST)
                socket_enter_dead(s, SOCKET_FAILURE_RESOURCES);
        else
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_FAILURE_RESOURCES);
}

static int socket_start(Unit *u) {
        Socket *s = SOCKET(u);
        int r;

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (IN_SET(s->state,
                   SOCKET_STOP_PRE,
                   SOCKET_STOP_PRE_SIGKILL,
                   SOCKET_STOP_PRE_SIGTERM,
                   SOCKET_STOP_POST,
                   SOCKET_FINAL_SIGTERM,
                   SOCKET_FINAL_SIGKILL,
                   SOCKET_CLEANING))
                return -EAGAIN;

        /* Already on it! */
        if (IN_SET(s->state,
                   SOCKET_START_PRE,
                   SOCKET_START_CHOWN,
                   SOCKET_START_POST))
                return 0;

        /* Cannot run this without the service being around */
        if (UNIT_ISSET(s->service)) {
                Service *service;

                service = SERVICE(UNIT_DEREF(s->service));

                if (UNIT(service)->load_state != UNIT_LOADED) {
                        log_unit_error(u, "Socket service %s not loaded, refusing.", UNIT(service)->id);
                        return -ENOENT;
                }

                /* If the service is already active we cannot start the
                 * socket */
                if (!IN_SET(service->state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_AUTO_RESTART)) {
                        log_unit_error(u, "Socket service %s already active, refusing.", UNIT(service)->id);
                        return -EBUSY;
                }
        }

        assert(IN_SET(s->state, SOCKET_DEAD, SOCKET_FAILED));

        r = unit_test_start_limit(u);
        if (r < 0) {
                socket_enter_dead(s, SOCKET_FAILURE_START_LIMIT_HIT);
                return r;
        }

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        s->result = SOCKET_SUCCESS;
        exec_command_reset_status_list_array(s->exec_command, _SOCKET_EXEC_COMMAND_MAX);

        u->reset_accounting = true;

        socket_enter_start_pre(s);
        return 1;
}

static int socket_stop(Unit *u) {
        Socket *s = SOCKET(u);

        assert(s);

        /* Already on it */
        if (IN_SET(s->state,
                   SOCKET_STOP_PRE,
                   SOCKET_STOP_PRE_SIGTERM,
                   SOCKET_STOP_PRE_SIGKILL,
                   SOCKET_STOP_POST,
                   SOCKET_FINAL_SIGTERM,
                   SOCKET_FINAL_SIGKILL))
                return 0;

        /* If there's already something running we go directly into
         * kill mode. */
        if (IN_SET(s->state,
                   SOCKET_START_PRE,
                   SOCKET_START_CHOWN,
                   SOCKET_START_POST)) {
                socket_enter_signal(s, SOCKET_STOP_PRE_SIGTERM, SOCKET_SUCCESS);
                return -EAGAIN;
        }

        /* If we are currently cleaning, then abort it, brutally. */
        if (s->state == SOCKET_CLEANING) {
                socket_enter_signal(s, SOCKET_FINAL_SIGKILL, SOCKET_SUCCESS);
                return 0;
        }

        assert(IN_SET(s->state, SOCKET_LISTENING, SOCKET_RUNNING));

        socket_enter_stop_pre(s, SOCKET_SUCCESS);
        return 1;
}

static int socket_serialize(Unit *u, FILE *f, FDSet *fds) {
        Socket *s = SOCKET(u);
        SocketPort *p;
        int r;

        assert(u);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", socket_state_to_string(s->state));
        (void) serialize_item(f, "result", socket_result_to_string(s->result));
        (void) serialize_item_format(f, "n-accepted", "%u", s->n_accepted);
        (void) serialize_item_format(f, "n-refused", "%u", s->n_refused);

        if (s->control_pid > 0)
                (void) serialize_item_format(f, "control-pid", PID_FMT, s->control_pid);

        if (s->control_command_id >= 0)
                (void) serialize_item(f, "control-command", socket_exec_command_to_string(s->control_command_id));

        LIST_FOREACH(port, p, s->ports) {
                int copy;

                if (p->fd < 0)
                        continue;

                copy = fdset_put_dup(fds, p->fd);
                if (copy < 0)
                        return log_unit_warning_errno(u, copy, "Failed to serialize socket fd: %m");

                if (p->type == SOCKET_SOCKET) {
                        _cleanup_free_ char *t = NULL;

                        r = socket_address_print(&p->address, &t);
                        if (r < 0)
                                return log_unit_error_errno(u, r, "Failed to format socket address: %m");

                        if (socket_address_family(&p->address) == AF_NETLINK)
                                (void) serialize_item_format(f, "netlink", "%i %s", copy, t);
                        else
                                (void) serialize_item_format(f, "socket", "%i %i %s", copy, p->address.type, t);
                } else if (p->type == SOCKET_SPECIAL)
                        (void) serialize_item_format(f, "special", "%i %s", copy, p->path);
                else if (p->type == SOCKET_MQUEUE)
                        (void) serialize_item_format(f, "mqueue", "%i %s", copy, p->path);
                else if (p->type == SOCKET_USB_FUNCTION)
                        (void) serialize_item_format(f, "ffs", "%i %s", copy, p->path);
                else {
                        assert(p->type == SOCKET_FIFO);
                        (void) serialize_item_format(f, "fifo", "%i %s", copy, p->path);
                }
        }

        return 0;
}

static void socket_port_take_fd(SocketPort *p, FDSet *fds, int fd) {
        assert(p);

        safe_close(p->fd);
        p->fd = fdset_remove(fds, fd);
}

static int socket_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Socket *s = SOCKET(u);

        assert(u);
        assert(key);
        assert(value);

        if (streq(key, "state")) {
                SocketState state;

                state = socket_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        s->deserialized_state = state;
        } else if (streq(key, "result")) {
                SocketResult f;

                f = socket_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != SOCKET_SUCCESS)
                        s->result = f;

        } else if (streq(key, "n-accepted")) {
                unsigned k;

                if (safe_atou(value, &k) < 0)
                        log_unit_debug(u, "Failed to parse n-accepted value: %s", value);
                else
                        s->n_accepted += k;
        } else if (streq(key, "n-refused")) {
                unsigned k;

                if (safe_atou(value, &k) < 0)
                        log_unit_debug(u, "Failed to parse n-refused value: %s", value);
                else
                        s->n_refused += k;
        } else if (streq(key, "control-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_unit_debug(u, "Failed to parse control-pid value: %s", value);
                else
                        s->control_pid = pid;
        } else if (streq(key, "control-command")) {
                SocketExecCommand id;

                id = socket_exec_command_from_string(value);
                if (id < 0)
                        log_unit_debug(u, "Failed to parse exec-command value: %s", value);
                else {
                        s->control_command_id = id;
                        s->control_command = s->exec_command[id];
                }
        } else if (streq(key, "fifo")) {
                int fd, skip = 0;
                SocketPort *p;

                if (sscanf(value, "%i %n", &fd, &skip) < 1 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse fifo value: %s", value);
                else
                        LIST_FOREACH(port, p, s->ports)
                                if (p->type == SOCKET_FIFO &&
                                    path_equal_or_files_same(p->path, value+skip, 0)) {
                                        socket_port_take_fd(p, fds, fd);
                                        break;
                                }

        } else if (streq(key, "special")) {
                int fd, skip = 0;
                SocketPort *p;

                if (sscanf(value, "%i %n", &fd, &skip) < 1 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse special value: %s", value);
                else
                        LIST_FOREACH(port, p, s->ports)
                                if (p->type == SOCKET_SPECIAL &&
                                    path_equal_or_files_same(p->path, value+skip, 0)) {
                                        socket_port_take_fd(p, fds, fd);
                                        break;
                                }

        } else if (streq(key, "mqueue")) {
                int fd, skip = 0;
                SocketPort *p;

                if (sscanf(value, "%i %n", &fd, &skip) < 1 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse mqueue value: %s", value);
                else
                        LIST_FOREACH(port, p, s->ports)
                                if (p->type == SOCKET_MQUEUE &&
                                    streq(p->path, value+skip)) {
                                        socket_port_take_fd(p, fds, fd);
                                        break;
                                }

        } else if (streq(key, "socket")) {
                int fd, type, skip = 0;
                SocketPort *p;

                if (sscanf(value, "%i %i %n", &fd, &type, &skip) < 2 || fd < 0 || type < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse socket value: %s", value);
                else
                        LIST_FOREACH(port, p, s->ports)
                                if (socket_address_is(&p->address, value+skip, type)) {
                                        socket_port_take_fd(p, fds, fd);
                                        break;
                                }

        } else if (streq(key, "netlink")) {
                int fd, skip = 0;
                SocketPort *p;

                if (sscanf(value, "%i %n", &fd, &skip) < 1 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse socket value: %s", value);
                else
                        LIST_FOREACH(port, p, s->ports)
                                if (socket_address_is_netlink(&p->address, value+skip)) {
                                        socket_port_take_fd(p, fds, fd);
                                        break;
                                }

        } else if (streq(key, "ffs")) {
                int fd, skip = 0;
                SocketPort *p;

                if (sscanf(value, "%i %n", &fd, &skip) < 1 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse ffs value: %s", value);
                else
                        LIST_FOREACH(port, p, s->ports)
                                if (p->type == SOCKET_USB_FUNCTION &&
                                    path_equal_or_files_same(p->path, value+skip, 0)) {
                                        socket_port_take_fd(p, fds, fd);
                                        break;
                                }

        } else
                log_unit_debug(UNIT(s), "Unknown serialization key: %s", key);

        return 0;
}

static void socket_distribute_fds(Unit *u, FDSet *fds) {
        Socket *s = SOCKET(u);
        SocketPort *p;

        assert(u);

        LIST_FOREACH(port, p, s->ports) {
                Iterator i;
                int fd;

                if (p->type != SOCKET_SOCKET)
                        continue;

                if (p->fd >= 0)
                        continue;

                FDSET_FOREACH(fd, fds, i) {
                        if (socket_address_matches_fd(&p->address, fd)) {
                                p->fd = fdset_remove(fds, fd);
                                s->deserialized_state = SOCKET_LISTENING;
                                break;
                        }
                }
        }
}

_pure_ static UnitActiveState socket_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SOCKET(u)->state];
}

_pure_ static const char *socket_sub_state_to_string(Unit *u) {
        assert(u);

        return socket_state_to_string(SOCKET(u)->state);
}

const char* socket_port_type_to_string(SocketPort *p) {

        assert(p);

        switch (p->type) {

        case SOCKET_SOCKET:

                switch (p->address.type) {

                case SOCK_STREAM:
                        return "Stream";

                case SOCK_DGRAM:
                        return "Datagram";

                case SOCK_SEQPACKET:
                        return "SequentialPacket";

                case SOCK_RAW:
                        if (socket_address_family(&p->address) == AF_NETLINK)
                                return "Netlink";

                        _fallthrough_;
                default:
                        return NULL;
                }

        case SOCKET_SPECIAL:
                return "Special";

        case SOCKET_MQUEUE:
                return "MessageQueue";

        case SOCKET_FIFO:
                return "FIFO";

        case SOCKET_USB_FUNCTION:
                return "USBFunction";

        default:
                return NULL;
        }
}

SocketType socket_port_type_from_string(const char *s) {
        assert(s);

        if (STR_IN_SET(s, "Stream", "Datagram", "SequentialPacket", "Netlink"))
                return SOCKET_SOCKET;
        else if (streq(s, "Special"))
                return SOCKET_SPECIAL;
        else if (streq(s, "MessageQueue"))
                return SOCKET_MQUEUE;
        else if (streq(s, "FIFO"))
                return SOCKET_FIFO;
        else if (streq(s, "USBFunction"))
                return SOCKET_USB_FUNCTION;
        else
                return _SOCKET_TYPE_INVALID;
}

_pure_ static bool socket_may_gc(Unit *u) {
        Socket *s = SOCKET(u);

        assert(u);

        return s->n_connections == 0;
}

static int socket_accept_do(Socket *s, int fd) {
        int cfd;

        assert(s);
        assert(fd >= 0);

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0)
                /* Convert transient network errors into clean and well-defined EAGAIN */
                return ERRNO_IS_ACCEPT_AGAIN(errno) ? -EAGAIN : -errno;

        return cfd;
}

static int socket_accept_in_cgroup(Socket *s, SocketPort *p, int fd) {
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        int cfd, r;
        pid_t pid;

        assert(s);
        assert(p);
        assert(fd >= 0);

        /* Similar to socket_address_listen_in_cgroup(), but for accept() rather than socket(): make sure that any
         * connection socket is also properly associated with the cgroup. */

        if (!IN_SET(p->address.sockaddr.sa.sa_family, AF_INET, AF_INET6))
                goto shortcut;

        r = bpf_firewall_supported();
        if (r < 0)
                return r;
        if (r == BPF_FIREWALL_UNSUPPORTED)
                goto shortcut;

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) < 0)
                return log_unit_error_errno(UNIT(s), errno, "Failed to create communication channel: %m");

        r = unit_fork_helper_process(UNIT(s), "(sd-accept)", &pid);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to fork off accept stub process: %m");
        if (r == 0) {
                /* Child */

                pair[0] = safe_close(pair[0]);

                cfd = socket_accept_do(s, fd);
                if (cfd == -EAGAIN) /* spurious accept() */
                        _exit(EXIT_SUCCESS);
                if (cfd < 0) {
                        log_unit_error_errno(UNIT(s), cfd, "Failed to accept connection socket: %m");
                        _exit(EXIT_FAILURE);
                }

                r = send_one_fd(pair[1], cfd, 0);
                if (r < 0) {
                        log_unit_error_errno(UNIT(s), r, "Failed to send connection socket to parent: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);
        cfd = receive_one_fd(pair[0], 0);

        /* We synchronously wait for the helper, as it shouldn't be slow */
        r = wait_for_terminate_and_check("(sd-accept)", pid, WAIT_LOG_ABNORMAL);
        if (r < 0) {
                safe_close(cfd);
                return r;
        }

        /* If we received no fd, we got EIO here. If this happens with a process exit code of EXIT_SUCCESS
         * this is a spurious accept(), let's convert that back to EAGAIN here. */
        if (cfd == -EIO)
                return -EAGAIN;
        if (cfd < 0)
                return log_unit_error_errno(UNIT(s), cfd, "Failed to receive connection socket: %m");

        return cfd;

shortcut:
        cfd = socket_accept_do(s, fd);
        if (cfd == -EAGAIN) /* spurious accept(), skip it silently */
                return -EAGAIN;
        if (cfd < 0)
                return log_unit_error_errno(UNIT(s), cfd, "Failed to accept connection socket: %m");

        return cfd;
}

static int socket_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        SocketPort *p = userdata;
        int cfd = -1;

        assert(p);
        assert(fd >= 0);

        if (p->socket->state != SOCKET_LISTENING)
                return 0;

        log_unit_debug(UNIT(p->socket), "Incoming traffic");

        if (revents != EPOLLIN) {
                if (revents & EPOLLHUP)
                        log_unit_error(UNIT(p->socket), "Got POLLHUP on a listening socket. The service probably invoked shutdown() on it, and should better not do that.");
                else
                        log_unit_error(UNIT(p->socket), "Got unexpected poll event (0x%x) on socket.", revents);
                goto fail;
        }

        if (p->socket->accept &&
            p->type == SOCKET_SOCKET &&
            socket_address_can_accept(&p->address)) {

                cfd = socket_accept_in_cgroup(p->socket, p, fd);
                if (cfd == -EAGAIN) /* Spurious accept() */
                        return 0;
                if (cfd < 0)
                        goto fail;

                socket_apply_socket_options(p->socket, cfd);
        }

        socket_enter_running(p->socket, cfd);
        return 0;

fail:
        socket_enter_stop_pre(p->socket, SOCKET_FAILURE_RESOURCES);
        return 0;
}

static void socket_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Socket *s = SOCKET(u);
        SocketResult f;

        assert(s);
        assert(pid >= 0);

        if (pid != s->control_pid)
                return;

        s->control_pid = 0;

        if (is_clean_exit(code, status, EXIT_CLEAN_COMMAND, NULL))
                f = SOCKET_SUCCESS;
        else if (code == CLD_EXITED)
                f = SOCKET_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = SOCKET_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = SOCKET_FAILURE_CORE_DUMP;
        else
                assert_not_reached("Unknown sigchld code");

        if (s->control_command) {
                exec_status_exit(&s->control_command->exec_status, &s->exec_context, pid, code, status);

                if (s->control_command->flags & EXEC_COMMAND_IGNORE_FAILURE)
                        f = SOCKET_SUCCESS;
        }

        unit_log_process_exit(
                        u,
                        "Control process",
                        socket_exec_command_to_string(s->control_command_id),
                        f == SOCKET_SUCCESS,
                        code, status);

        if (s->result == SOCKET_SUCCESS)
                s->result = f;

        if (s->control_command &&
            s->control_command->command_next &&
            f == SOCKET_SUCCESS) {

                log_unit_debug(u, "Running next command for state %s", socket_state_to_string(s->state));
                socket_run_next(s);
        } else {
                s->control_command = NULL;
                s->control_command_id = _SOCKET_EXEC_COMMAND_INVALID;

                /* No further commands for this step, so let's figure
                 * out what to do next */

                log_unit_debug(u, "Got final SIGCHLD for state %s", socket_state_to_string(s->state));

                switch (s->state) {

                case SOCKET_START_PRE:
                        if (f == SOCKET_SUCCESS)
                                socket_enter_start_chown(s);
                        else
                                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, f);
                        break;

                case SOCKET_START_CHOWN:
                        if (f == SOCKET_SUCCESS)
                                socket_enter_start_post(s);
                        else
                                socket_enter_stop_pre(s, f);
                        break;

                case SOCKET_START_POST:
                        if (f == SOCKET_SUCCESS)
                                socket_enter_listening(s);
                        else
                                socket_enter_stop_pre(s, f);
                        break;

                case SOCKET_STOP_PRE:
                case SOCKET_STOP_PRE_SIGTERM:
                case SOCKET_STOP_PRE_SIGKILL:
                        socket_enter_stop_post(s, f);
                        break;

                case SOCKET_STOP_POST:
                case SOCKET_FINAL_SIGTERM:
                case SOCKET_FINAL_SIGKILL:
                        socket_enter_dead(s, f);
                        break;

                case SOCKET_CLEANING:

                        if (s->clean_result == SOCKET_SUCCESS)
                                s->clean_result = f;

                        socket_enter_dead(s, SOCKET_SUCCESS);
                        break;

                default:
                        assert_not_reached("Uh, control process died at wrong time.");
                }
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);
}

static int socket_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Socket *s = SOCKET(userdata);

        assert(s);
        assert(s->timer_event_source == source);

        switch (s->state) {

        case SOCKET_START_PRE:
                log_unit_warning(UNIT(s), "Starting timed out. Terminating.");
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_FAILURE_TIMEOUT);
                break;

        case SOCKET_START_CHOWN:
        case SOCKET_START_POST:
                log_unit_warning(UNIT(s), "Starting timed out. Stopping.");
                socket_enter_stop_pre(s, SOCKET_FAILURE_TIMEOUT);
                break;

        case SOCKET_STOP_PRE:
                log_unit_warning(UNIT(s), "Stopping timed out. Terminating.");
                socket_enter_signal(s, SOCKET_STOP_PRE_SIGTERM, SOCKET_FAILURE_TIMEOUT);
                break;

        case SOCKET_STOP_PRE_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "Stopping timed out. Killing.");
                        socket_enter_signal(s, SOCKET_STOP_PRE_SIGKILL, SOCKET_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "Stopping timed out. Skipping SIGKILL. Ignoring.");
                        socket_enter_stop_post(s, SOCKET_FAILURE_TIMEOUT);
                }
                break;

        case SOCKET_STOP_PRE_SIGKILL:
                log_unit_warning(UNIT(s), "Processes still around after SIGKILL. Ignoring.");
                socket_enter_stop_post(s, SOCKET_FAILURE_TIMEOUT);
                break;

        case SOCKET_STOP_POST:
                log_unit_warning(UNIT(s), "Stopping timed out (2). Terminating.");
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_FAILURE_TIMEOUT);
                break;

        case SOCKET_FINAL_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "Stopping timed out (2). Killing.");
                        socket_enter_signal(s, SOCKET_FINAL_SIGKILL, SOCKET_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "Stopping timed out (2). Skipping SIGKILL. Ignoring.");
                        socket_enter_dead(s, SOCKET_FAILURE_TIMEOUT);
                }
                break;

        case SOCKET_FINAL_SIGKILL:
                log_unit_warning(UNIT(s), "Still around after SIGKILL (2). Entering failed mode.");
                socket_enter_dead(s, SOCKET_FAILURE_TIMEOUT);
                break;

        case SOCKET_CLEANING:
                log_unit_warning(UNIT(s), "Cleaning timed out. killing.");

                if (s->clean_result == SOCKET_SUCCESS)
                        s->clean_result = SOCKET_FAILURE_TIMEOUT;

                socket_enter_signal(s, SOCKET_FINAL_SIGKILL, 0);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

int socket_collect_fds(Socket *s, int **fds) {
        size_t k = 0, n = 0;
        SocketPort *p;
        int *rfds;

        assert(s);
        assert(fds);

        /* Called from the service code for requesting our fds */

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd >= 0)
                        n++;
                n += p->n_auxiliary_fds;
        }

        if (n <= 0) {
                *fds = NULL;
                return 0;
        }

        rfds = new(int, n);
        if (!rfds)
                return -ENOMEM;

        LIST_FOREACH(port, p, s->ports) {
                size_t i;

                if (p->fd >= 0)
                        rfds[k++] = p->fd;
                for (i = 0; i < p->n_auxiliary_fds; ++i)
                        rfds[k++] = p->auxiliary_fds[i];
        }

        assert(k == n);

        *fds = rfds;
        return (int) n;
}

static void socket_reset_failed(Unit *u) {
        Socket *s = SOCKET(u);

        assert(s);

        if (s->state == SOCKET_FAILED)
                socket_set_state(s, SOCKET_DEAD);

        s->result = SOCKET_SUCCESS;
        s->clean_result = SOCKET_SUCCESS;
}

void socket_connection_unref(Socket *s) {
        assert(s);

        /* The service is dead. Yay!
         *
         * This is strictly for one-instance-per-connection
         * services. */

        assert(s->n_connections > 0);
        s->n_connections--;

        log_unit_debug(UNIT(s), "One connection closed, %u left.", s->n_connections);
}

static void socket_trigger_notify(Unit *u, Unit *other) {
        Socket *s = SOCKET(u);

        assert(u);
        assert(other);

        /* Filter out invocations with bogus state */
        if (other->load_state != UNIT_LOADED || other->type != UNIT_SERVICE)
                return;

        /* Don't propagate state changes from the service if we are already down */
        if (!IN_SET(s->state, SOCKET_RUNNING, SOCKET_LISTENING))
                return;

        /* We don't care for the service state if we are in Accept=yes mode */
        if (s->accept)
                return;

        /* Propagate start limit hit state */
        if (other->start_limit_hit) {
                socket_enter_stop_pre(s, SOCKET_FAILURE_SERVICE_START_LIMIT_HIT);
                return;
        }

        /* Don't propagate anything if there's still a job queued */
        if (other->job)
                return;

        if (IN_SET(SERVICE(other)->state,
                   SERVICE_DEAD, SERVICE_FAILED,
                   SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                   SERVICE_AUTO_RESTART))
               socket_enter_listening(s);

        if (SERVICE(other)->state == SERVICE_RUNNING)
                socket_set_state(s, SOCKET_RUNNING);
}

static int socket_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        return unit_kill_common(u, who, signo, -1, SOCKET(u)->control_pid, error);
}

static int socket_get_timeout(Unit *u, usec_t *timeout) {
        Socket *s = SOCKET(u);
        usec_t t;
        int r;

        if (!s->timer_event_source)
                return 0;

        r = sd_event_source_get_time(s->timer_event_source, &t);
        if (r < 0)
                return r;
        if (t == USEC_INFINITY)
                return 0;

        *timeout = t;
        return 1;
}

char *socket_fdname(Socket *s) {
        assert(s);

        /* Returns the name to use for $LISTEN_NAMES. If the user
         * didn't specify anything specifically, use the socket unit's
         * name as fallback. */

        return s->fdname ?: UNIT(s)->id;
}

static int socket_control_pid(Unit *u) {
        Socket *s = SOCKET(u);

        assert(s);

        return s->control_pid;
}

static int socket_clean(Unit *u, ExecCleanMask mask) {
        _cleanup_strv_free_ char **l = NULL;
        Socket *s = SOCKET(u);
        int r;

        assert(s);
        assert(mask != 0);

        if (s->state != SOCKET_DEAD)
                return -EBUSY;

        r = exec_context_get_clean_directories(&s->exec_context, u->manager->prefix, mask, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l))
                return -EUNATCH;

        socket_unwatch_control_pid(s);
        s->clean_result = SOCKET_SUCCESS;
        s->control_command = NULL;
        s->control_command_id = _SOCKET_EXEC_COMMAND_INVALID;

        r = socket_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->exec_context.timeout_clean_usec));
        if (r < 0)
                goto fail;

        r = unit_fork_and_watch_rm_rf(u, l, &s->control_pid);
        if (r < 0)
                goto fail;

        socket_set_state(s, SOCKET_CLEANING);

        return 0;

fail:
        log_unit_warning_errno(u, r, "Failed to initiate cleaning: %m");
        s->clean_result = SOCKET_FAILURE_RESOURCES;
        s->timer_event_source = sd_event_source_unref(s->timer_event_source);
        return r;
}

static int socket_can_clean(Unit *u, ExecCleanMask *ret) {
        Socket *s = SOCKET(u);

        assert(s);

        return exec_context_get_clean_mask(&s->exec_context, ret);
}

static const char* const socket_exec_command_table[_SOCKET_EXEC_COMMAND_MAX] = {
        [SOCKET_EXEC_START_PRE] = "ExecStartPre",
        [SOCKET_EXEC_START_CHOWN] = "ExecStartChown",
        [SOCKET_EXEC_START_POST] = "ExecStartPost",
        [SOCKET_EXEC_STOP_PRE] = "ExecStopPre",
        [SOCKET_EXEC_STOP_POST] = "ExecStopPost"
};

DEFINE_STRING_TABLE_LOOKUP(socket_exec_command, SocketExecCommand);

static const char* const socket_result_table[_SOCKET_RESULT_MAX] = {
        [SOCKET_SUCCESS] = "success",
        [SOCKET_FAILURE_RESOURCES] = "resources",
        [SOCKET_FAILURE_TIMEOUT] = "timeout",
        [SOCKET_FAILURE_EXIT_CODE] = "exit-code",
        [SOCKET_FAILURE_SIGNAL] = "signal",
        [SOCKET_FAILURE_CORE_DUMP] = "core-dump",
        [SOCKET_FAILURE_START_LIMIT_HIT] = "start-limit-hit",
        [SOCKET_FAILURE_TRIGGER_LIMIT_HIT] = "trigger-limit-hit",
        [SOCKET_FAILURE_SERVICE_START_LIMIT_HIT] = "service-start-limit-hit"
};

DEFINE_STRING_TABLE_LOOKUP(socket_result, SocketResult);

const UnitVTable socket_vtable = {
        .object_size = sizeof(Socket),
        .exec_context_offset = offsetof(Socket, exec_context),
        .cgroup_context_offset = offsetof(Socket, cgroup_context),
        .kill_context_offset = offsetof(Socket, kill_context),
        .exec_runtime_offset = offsetof(Socket, exec_runtime),
        .dynamic_creds_offset = offsetof(Socket, dynamic_creds),

        .sections =
                "Unit\0"
                "Socket\0"
                "Install\0",
        .private_section = "Socket",

        .can_transient = true,

        .init = socket_init,
        .done = socket_done,
        .load = socket_load,

        .coldplug = socket_coldplug,

        .dump = socket_dump,

        .start = socket_start,
        .stop = socket_stop,

        .kill = socket_kill,
        .clean = socket_clean,
        .can_clean = socket_can_clean,

        .get_timeout = socket_get_timeout,

        .serialize = socket_serialize,
        .deserialize_item = socket_deserialize_item,
        .distribute_fds = socket_distribute_fds,

        .active_state = socket_active_state,
        .sub_state_to_string = socket_sub_state_to_string,

        .will_restart = unit_will_restart_default,

        .may_gc = socket_may_gc,

        .sigchld_event = socket_sigchld_event,

        .trigger_notify = socket_trigger_notify,

        .reset_failed = socket_reset_failed,

        .control_pid = socket_control_pid,

        .bus_vtable = bus_socket_vtable,
        .bus_set_property = bus_socket_set_property,
        .bus_commit_properties = bus_socket_commit_properties,

        .status_message_formats = {
                /*.starting_stopping = {
                        [0] = "Starting socket %s...",
                        [1] = "Stopping socket %s...",
                },*/
                .finished_start_job = {
                        [JOB_DONE]       = "Listening on %s.",
                        [JOB_FAILED]     = "Failed to listen on %s.",
                        [JOB_TIMEOUT]    = "Timed out starting %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Closed %s.",
                        [JOB_FAILED]     = "Failed stopping %s.",
                        [JOB_TIMEOUT]    = "Timed out stopping %s.",
                },
        },
};
