/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/sctp.h>
#include <mqueue.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bpf-program.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "copy.h"
#include "dbus-socket.h"
#include "dbus-unit.h"
#include "errno-list.h"
#include "errno-util.h"
#include "exit-status.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fdset.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "ip-protocol-list.h"
#include "log.h"
#include "manager.h"
#include "mkdir-label.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "selinux-util.h"
#include "serialize.h"
#include "service.h"
#include "set.h"
#include "siphash24.h"
#include "smack-util.h"
#include "socket.h"
#include "socket-netlink.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit.h"
#include "unit-name.h"
#include "user-util.h"

typedef struct SocketPeer {
        unsigned n_ref;

        Socket *socket;
        union sockaddr_union peer;
        socklen_t peer_salen;
        struct ucred peer_cred;
} SocketPeer;

static const UnitActiveState state_translation_table[_SOCKET_STATE_MAX] = {
        [SOCKET_DEAD]             = UNIT_INACTIVE,
        [SOCKET_START_PRE]        = UNIT_ACTIVATING,
        [SOCKET_START_OPEN]       = UNIT_ACTIVATING,
        [SOCKET_START_CHOWN]      = UNIT_ACTIVATING,
        [SOCKET_START_POST]       = UNIT_ACTIVATING,
        [SOCKET_LISTENING]        = UNIT_ACTIVE,
        [SOCKET_DEFERRED]         = UNIT_ACTIVE,
        [SOCKET_RUNNING]          = UNIT_ACTIVE,
        [SOCKET_STOP_PRE]         = UNIT_DEACTIVATING,
        [SOCKET_STOP_PRE_SIGTERM] = UNIT_DEACTIVATING,
        [SOCKET_STOP_PRE_SIGKILL] = UNIT_DEACTIVATING,
        [SOCKET_STOP_POST]        = UNIT_DEACTIVATING,
        [SOCKET_FINAL_SIGTERM]    = UNIT_DEACTIVATING,
        [SOCKET_FINAL_SIGKILL]    = UNIT_DEACTIVATING,
        [SOCKET_FAILED]           = UNIT_FAILED,
        [SOCKET_CLEANING]         = UNIT_MAINTENANCE,
};

static int socket_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int socket_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);

static bool SOCKET_STATE_WITH_PROCESS(SocketState state) {
        return IN_SET(state,
                      SOCKET_START_PRE,
                      SOCKET_START_CHOWN,
                      SOCKET_START_POST,
                      SOCKET_STOP_PRE,
                      SOCKET_STOP_PRE_SIGTERM,
                      SOCKET_STOP_PRE_SIGKILL,
                      SOCKET_STOP_POST,
                      SOCKET_FINAL_SIGTERM,
                      SOCKET_FINAL_SIGKILL,
                      SOCKET_CLEANING);
}

static bool SOCKET_SERVICE_IS_ACTIVE(Service *s, bool allow_finalize) {
        assert(s);

        /* If unit_active_state() reports inactive/failed then it's all good, otherwise we need to
         * manually exclude SERVICE_AUTO_RESTART and SERVICE_AUTO_RESTART_QUEUED, in which cases
         * the start job hasn't been enqueued/run, but are only placeholders in order to allow
         * canceling auto restart. */

        if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(UNIT(s))))
                return false;

        if (IN_SET(s->state, SERVICE_AUTO_RESTART, SERVICE_AUTO_RESTART_QUEUED))
                return false;

        if (allow_finalize && IN_SET(s->state, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL, SERVICE_CLEANING))
                return false;

        return true;
}

static void socket_init(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));

        assert(u->load_state == UNIT_STUB);

        s->backlog = SOMAXCONN_DELUXE;
        s->timeout_usec = u->manager->defaults.timeout_start_usec;
        s->directory_mode = 0755;
        s->socket_mode = 0666;

        s->max_connections = 64;

        s->pass_rights = true; /* defaults to enabled in kernel */
        s->priority = -1;
        s->ip_tos = -1;
        s->ip_ttl = -1;
        s->mark = -1;

        s->exec_context.std_output = u->manager->defaults.std_output;
        s->exec_context.std_error = u->manager->defaults.std_error;

        s->control_pid = PIDREF_NULL;
        s->control_command_id = _SOCKET_EXEC_COMMAND_INVALID;

        s->trigger_limit = RATELIMIT_OFF;

        s->poll_limit = RATELIMIT_OFF;

        s->defer_trigger_max_usec = USEC_INFINITY;
}

static void socket_unwatch_control_pid(Socket *s) {
        assert(s);
        unit_unwatch_pidref_done(UNIT(s), &s->control_pid);
}

static void socket_port_close_auxiliary_fds(SocketPort *p) {
        assert(p);

        close_many(p->auxiliary_fds, p->n_auxiliary_fds);
        p->auxiliary_fds = mfree(p->auxiliary_fds);
        p->n_auxiliary_fds = 0;
}

SocketPort* socket_port_free(SocketPort *p) {
        if (!p)
                return NULL;

        sd_event_source_unref(p->event_source);

        socket_port_close_auxiliary_fds(p);
        safe_close(p->fd);
        free(p->path);

        return mfree(p);
}

void socket_free_ports(Socket *s) {
        assert(s);

        LIST_CLEAR(port, s->ports, socket_port_free);
}

static void socket_done(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        SocketPeer *p;

        socket_free_ports(s);

        while ((p = set_steal_first(s->peers_by_address)))
                p->socket = NULL;

        s->peers_by_address = set_free(s->peers_by_address);

        s->exec_runtime = exec_runtime_free(s->exec_runtime);

        exec_command_free_array(s->exec_command, _SOCKET_EXEC_COMMAND_MAX);
        s->control_command = NULL;

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

        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
}

static int socket_arm_timer(Socket *s, bool relative, usec_t usec) {
        assert(s);

        return unit_arm_timer(UNIT(s), &s->timer_event_source, relative, usec, socket_dispatch_timer);
}

static bool have_non_accept_socket(Socket *s) {
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

                r = unit_add_mounts_for(UNIT(s), path, UNIT_DEPENDENCY_FILE, UNIT_MOUNT_REQUIRES);
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
        return unit_add_node_dependency(UNIT(s), t, UNIT_BINDS_TO, UNIT_DEPENDENCY_FILE);
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

static bool socket_has_exec(Socket *s) {
        assert(s);

        FOREACH_ARRAY(i, s->exec_command, _SOCKET_EXEC_COMMAND_MAX)
                if (*i)
                        return true;

        return false;
}

static int socket_add_extras(Socket *s) {
        Unit *u = UNIT(ASSERT_PTR(s));
        int r;

        /* Pick defaults for the trigger limit, if nothing was explicitly configured. We pick a relatively high limit
         * in Accept=yes mode, and a lower limit for Accept=no. Reason: in Accept=yes mode we are invoking accept()
         * ourselves before the trigger limit can hit, thus incoming connections are taken off the socket queue quickly
         * and reliably. This is different for Accept=no, where the spawned service has to take the incoming traffic
         * off the queues, which it might not necessarily do. Moreover, while Accept=no services are supposed to
         * process whatever is queued in one go, and thus should normally never have to be started frequently. This is
         * different for Accept=yes where each connection is processed by a new service instance, and thus frequent
         * service starts are typical.
         *
         * For the poll limit we follow a similar rule, but use 3/4th of the trigger limit parameters, to
         * trigger this earlier. */

        if (s->trigger_limit.interval == USEC_INFINITY)
                s->trigger_limit.interval = 2 * USEC_PER_SEC;
        if (s->trigger_limit.burst == UINT_MAX)
                s->trigger_limit.burst = s->accept ? 200 : 20;

        if (s->poll_limit.interval == USEC_INFINITY)
                s->poll_limit.interval = 2 * USEC_PER_SEC;
        if (s->poll_limit.burst == UINT_MAX)
                s->poll_limit.burst = s->accept ? 150 : 15;

        if (have_non_accept_socket(s)) {

                if (!UNIT_ISSET(s->service)) {
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

static const char* socket_find_symlink_target(Socket *s) {
        const char *found = NULL;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                const char *f;

                switch (p->type) {

                case SOCKET_FIFO:
                        f = p->path;
                        break;

                case SOCKET_SOCKET:
                        f = socket_address_get_path(&p->address);
                        break;

                default:
                        f = NULL;
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
        assert(UNIT(s)->load_state == UNIT_LOADED);

        if (!s->ports)
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Unit has no Listen setting (ListenStream=, ListenDatagram=, ListenFIFO=, ...). Refusing.");

        if (s->max_connections <= 0)
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "MaxConnection= setting too small. Refusing.");

        if (s->accept && have_non_accept_socket(s))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Unit configured for accepting sockets, but sockets are non-accepting. Refusing.");

        if (s->accept && UNIT_ISSET(s->service))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Explicit service configuration for accepting socket units not supported. Refusing.");

        if (s->accept && s->defer_trigger != SOCKET_DEFER_NO)
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Socket unit is configured to be accepting with DeferTrigger= enabled. Refusing.");

        if (!strv_isempty(s->symlinks) && !socket_find_symlink_target(s))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Unit has symlinks set but none or more than one node in the file system. Refusing.");

        return 0;
}

static void peer_address_hash_func(const SocketPeer *s, struct siphash *state) {
        assert(s);

        if (s->peer.sa.sa_family == AF_INET)
                siphash24_compress_typesafe(s->peer.in.sin_addr, state);
        else if (s->peer.sa.sa_family == AF_INET6)
                siphash24_compress_typesafe(s->peer.in6.sin6_addr, state);
        else if (s->peer.sa.sa_family == AF_VSOCK)
                siphash24_compress_typesafe(s->peer.vm.svm_cid, state);
        else if (s->peer.sa.sa_family == AF_UNIX)
                siphash24_compress_typesafe(s->peer_cred.uid, state);
        else
                assert_not_reached();
}

static int peer_address_compare_func(const SocketPeer *x, const SocketPeer *y) {
        int r;

        r = CMP(x->peer.sa.sa_family, y->peer.sa.sa_family);
        if (r != 0)
                return r;

        switch (x->peer.sa.sa_family) {
        case AF_INET:
                return memcmp(&x->peer.in.sin_addr, &y->peer.in.sin_addr, sizeof(x->peer.in.sin_addr));
        case AF_INET6:
                return memcmp(&x->peer.in6.sin6_addr, &y->peer.in6.sin6_addr, sizeof(x->peer.in6.sin6_addr));
        case AF_VSOCK:
                return CMP(x->peer.vm.svm_cid, y->peer.vm.svm_cid);
        case AF_UNIX:
                return CMP(x->peer_cred.uid, y->peer_cred.uid);
        }
        assert_not_reached();
}

DEFINE_PRIVATE_HASH_OPS(peer_address_hash_ops, SocketPeer, peer_address_hash_func, peer_address_compare_func);

static int socket_load(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        int r;

        assert(u->load_state == UNIT_STUB);

        r = unit_load_fragment_and_dropin(u, true);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        /* This is a new unit? Then let's add in some extras */
        r = socket_add_extras(s);
        if (r < 0)
                return r;

        return socket_verify(s);
}

static SocketPeer* socket_peer_dup(const SocketPeer *q) {
        SocketPeer *p;

        assert(q);

        p = new(SocketPeer, 1);
        if (!p)
                return NULL;

        *p = (SocketPeer) {
                .n_ref = 1,
                .peer = q->peer,
                .peer_salen = q->peer_salen,
                .peer_cred = q->peer_cred,
        };

        return p;
}

static SocketPeer* socket_peer_free(SocketPeer *p) {
        assert(p);

        if (p->socket)
                set_remove(p->socket->peers_by_address, p);

        return mfree(p);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(SocketPeer, socket_peer, socket_peer_free);

int socket_acquire_peer(Socket *s, int fd, SocketPeer **ret) {
        _cleanup_(socket_peer_unrefp) SocketPeer *remote = NULL;
        SocketPeer key = {
                .peer_salen = sizeof(union sockaddr_union),
                .peer_cred = UCRED_INVALID,
        }, *i;
        int r;

        assert(s);
        assert(fd >= 0);
        assert(ret);

        if (getpeername(fd, &key.peer.sa, &key.peer_salen) < 0)
                return log_unit_error_errno(UNIT(s), errno, "getpeername() failed: %m");

        switch (key.peer.sa.sa_family) {
        case AF_INET:
        case AF_INET6:
        case AF_VSOCK:
                break;

        case AF_UNIX:
                r = getpeercred(fd, &key.peer_cred);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to get peer credentials of socket: %m");
                break;

        default:
                *ret = NULL;
                return 0;
        }

        i = set_get(s->peers_by_address, &key);
        if (i) {
                *ret = socket_peer_ref(i);
                return 1;
        }

        remote = socket_peer_dup(&key);
        if (!remote)
                return log_oom();

        r = set_ensure_put(&s->peers_by_address, &peer_address_hash_ops, remote);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to insert peer info into hash table: %m");

        remote->socket = s;

        *ret = TAKE_PTR(remote);
        return 1;
}

static const char* listen_lookup(int family, int type) {

        if (family == AF_NETLINK)
                return "ListenNetlink";

        if (type == SOCK_STREAM)
                return "ListenStream";
        else if (type == SOCK_DGRAM)
                return "ListenDatagram";
        else if (type == SOCK_SEQPACKET)
                return "ListenSequentialPacket";

        assert_not_reached();
}

static void socket_dump(Unit *u, FILE *f, const char *prefix) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        const char *prefix2, *str;

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
                "%sPassPIDFD: %s\n"
                "%sPassSecurity: %s\n"
                "%sPassPacketInfo: %s\n"
                "%sAcceptFileDescriptors: %s\n"
                "%sTCPCongestion: %s\n"
                "%sRemoveOnStop: %s\n"
                "%sWritable: %s\n"
                "%sFileDescriptorName: %s\n"
                "%sPassFileDescriptorsToExec: %s\n"
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
                prefix, yes_no(s->pass_pidfd),
                prefix, yes_no(s->pass_sec),
                prefix, yes_no(s->pass_pktinfo),
                prefix, yes_no(s->pass_rights),
                prefix, strna(s->tcp_congestion),
                prefix, yes_no(s->remove_on_stop),
                prefix, yes_no(s->writable),
                prefix, socket_fdname(s),
                prefix, yes_no(s->pass_fds_to_exec),
                prefix, yes_no(s->selinux_context_from_net));

        if (s->timestamping != SOCKET_TIMESTAMPING_OFF)
                fprintf(f,
                        "%sTimestamping: %s\n",
                        prefix, socket_timestamping_to_string(s->timestamping));

        if (pidref_is_set(&s->control_pid))
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, s->control_pid.pid);

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
        else
                fprintf(f,
                        "%sFlushPending: %s\n"
                        "%sDeferTrigger: %s\n"
                        "%sDeferTriggerMaxSec: %s\n",
                        prefix, yes_no(s->flush_pending),
                        prefix, socket_defer_trigger_to_string(s->defer_trigger),
                        prefix, FORMAT_TIMESPAN(s->defer_trigger_max_usec, USEC_PER_SEC));

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

        if (timestamp_is_set(s->keep_alive_time))
                fprintf(f,
                        "%sKeepAliveTimeSec: %s\n",
                        prefix, FORMAT_TIMESPAN(s->keep_alive_time, USEC_PER_SEC));

        if (s->keep_alive_interval > 0)
                fprintf(f,
                        "%sKeepAliveIntervalSec: %s\n",
                        prefix, FORMAT_TIMESPAN(s->keep_alive_interval, USEC_PER_SEC));

        if (s->keep_alive_cnt > 0)
                fprintf(f,
                        "%sKeepAliveProbes: %u\n",
                        prefix, s->keep_alive_cnt);

        if (s->defer_accept > 0)
                fprintf(f,
                        "%sDeferAcceptSec: %s\n",
                        prefix, FORMAT_TIMESPAN(s->defer_accept, USEC_PER_SEC));

        LIST_FOREACH(port, p, s->ports) {

                switch (p->type) {
                case SOCKET_SOCKET: {
                        _cleanup_free_ char *k = NULL;
                        int r;

                        r = socket_address_print(&p->address, &k);
                        if (r < 0) {
                                errno = -r;
                                fprintf(f, "%s%s: %m\n", prefix, listen_lookup(socket_address_family(&p->address), p->address.type));
                        } else
                                fprintf(f, "%s%s: %s\n", prefix, listen_lookup(socket_address_family(&p->address), p->address.type), k);
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
                "%sTriggerLimitBurst: %u\n"
                "%sPollLimitIntervalSec: %s\n"
                "%sPollLimitBurst: %u\n",
                prefix, FORMAT_TIMESPAN(s->trigger_limit.interval, USEC_PER_SEC),
                prefix, s->trigger_limit.burst,
                prefix, FORMAT_TIMESPAN(s->poll_limit.interval, USEC_PER_SEC),
                prefix, s->poll_limit.burst);

        str = ip_protocol_to_name(s->socket_protocol);
        if (str)
                fprintf(f, "%sSocketProtocol: %s\n", prefix, str);

        if (!strv_isempty(s->symlinks)) {
                fprintf(f, "%sSymlinks:", prefix);
                STRV_FOREACH(q, s->symlinks)
                        fprintf(f, " %s", *q);

                fprintf(f, "\n");
        }

        fprintf(f,
                "%sTimeoutSec: %s\n",
                prefix, FORMAT_TIMESPAN(s->timeout_usec, USEC_PER_SEC));

        exec_context_dump(&s->exec_context, f, prefix);
        kill_context_dump(&s->kill_context, f, prefix);

        for (SocketExecCommand c = 0; c < _SOCKET_EXEC_COMMAND_MAX; c++) {
                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s%s %s:\n",
                        prefix, glyph(GLYPH_ARROW_RIGHT), socket_exec_command_to_string(c));

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

        cgroup_context_dump(UNIT(s), f, prefix);
}

static int instance_from_socket(
                int fd,
                unsigned nr,
                char **ret) {

        union sockaddr_union local, remote;
        socklen_t l;
        int r;

        assert(fd >= 0);
        assert(ret);

        l = sizeof(local);
        if (getsockname(fd, &local.sa, &l) < 0)
                return -errno;

        l = sizeof(remote);
        if (getpeername(fd, &remote.sa, &l) < 0)
                return -errno;

        uint64_t cookie;
        r = socket_get_cookie(fd, &cookie);
        if (r < 0)
                return r;

        char *s;

        switch (local.sa.sa_family) {

        case AF_INET: {
                uint32_t
                        a = be32toh(local.in.sin_addr.s_addr),
                        b = be32toh(remote.in.sin_addr.s_addr);

                if (asprintf(&s,
                             "%u-%" PRIu64 "-%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
                             nr,
                             cookie,
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

                        if (asprintf(&s,
                                     "%u-%" PRIu64 "-%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
                                     nr,
                                     cookie,
                                     a[0], a[1], a[2], a[3],
                                     be16toh(local.in6.sin6_port),
                                     b[0], b[1], b[2], b[3],
                                     be16toh(remote.in6.sin6_port)) < 0)
                                return -ENOMEM;
                } else {
                        if (asprintf(&s,
                                     "%u-%" PRIu64 "-%s:%u-%s:%u",
                                     nr,
                                     cookie,
                                     IN6_ADDR_TO_STRING(&local.in6.sin6_addr),
                                     be16toh(local.in6.sin6_port),
                                     IN6_ADDR_TO_STRING(&remote.in6.sin6_addr),
                                     be16toh(remote.in6.sin6_port)) < 0)
                                return -ENOMEM;
                }

                break;
        }

        case AF_UNIX: {
                struct ucred ucred;

                r = getpeercred(fd, &ucred);
                if (r >= 0) {
                        _cleanup_close_ int pidfd = getpeerpidfd(fd);
                        uint64_t pidfd_id;

                        if (pidfd >= 0 && pidfd_get_inode_id(pidfd, &pidfd_id) >= 0)
                                r = asprintf(&s, "%u-%" PRIu64 "-" PID_FMT "_%" PRIu64 "-" UID_FMT,
                                             nr, cookie, ucred.pid, pidfd_id, ucred.uid);
                        else
                                r = asprintf(&s, "%u-%" PRIu64 "-" PID_FMT "-" UID_FMT,
                                             nr, cookie, ucred.pid, ucred.uid);
                        if (r < 0)
                                return -ENOMEM;
                } else if (r == -ENODATA) {
                        /* This handles the case where somebody is connecting from another pid/uid namespace
                         * (e.g. from outside of our container). */
                        if (asprintf(&s,
                                     "%u-%" PRIu64 "-unknown",
                                     nr,
                                     cookie) < 0)
                                return -ENOMEM;
                } else
                        return r;

                break;
        }

        case AF_VSOCK:
                if (asprintf(&s,
                             "%u-%" PRIu64 "-%u:%u-%u:%u",
                             nr,
                             cookie,
                             local.vm.svm_cid, local.vm.svm_port,
                             remote.vm.svm_cid, remote.vm.svm_port) < 0)
                        return -ENOMEM;

                break;

        default:
                assert_not_reached();
        }

        *ret = s;
        return 0;
}

static void socket_close_fds(Socket *s) {
        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                bool was_open = p->fd >= 0;

                p->event_source = sd_event_source_disable_unref(p->event_source);
                p->fd = safe_close(p->fd);
                socket_port_close_auxiliary_fds(p);

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
                        ;
                }
        }

        if (s->remove_on_stop)
                STRV_FOREACH(i, s->symlinks)
                        (void) unlink(*i);

        /* Note that we don't return NULL here, since s has not been freed. */
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(Socket*, socket_close_fds, NULL);

#define log_socket_option_errno(s, e, option)                                          \
        ({                                                                             \
                int _e_ = (e);                                                         \
                log_unit_full_errno(                                                   \
                                UNIT(s),                                               \
                                ERRNO_IS_NOT_SUPPORTED(_e_) ||                         \
                                ERRNO_IS_PRIVILEGE(_e_) ? LOG_DEBUG : LOG_WARNING,     \
                                _e_,                                                   \
                                "Failed to set %s socket option, ignoring: %m",        \
                                option);                                               \
        })

static void socket_apply_socket_options(Socket *s, SocketPort *p, int fd) {
        int r;

        assert(s);
        assert(p);
        assert(fd >= 0);

        if (s->keep_alive) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, true);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_KEEPALIVE");
        }

        if (timestamp_is_set(s->keep_alive_time)) {
                r = setsockopt_int(fd, SOL_TCP, TCP_KEEPIDLE, s->keep_alive_time / USEC_PER_SEC);
                if (r < 0)
                        log_socket_option_errno(s, r, "TCP_KEEPIDLE");
        }

        if (s->keep_alive_interval > 0) {
                r = setsockopt_int(fd, SOL_TCP, TCP_KEEPINTVL, s->keep_alive_interval / USEC_PER_SEC);
                if (r < 0)
                        log_socket_option_errno(s, r, "TCP_KEEPINTVL");
        }

        if (s->keep_alive_cnt > 0) {
                r = setsockopt_int(fd, SOL_TCP, TCP_KEEPCNT, s->keep_alive_cnt);
                if (r < 0)
                        log_socket_option_errno(s, r, "TCP_KEEPCNT");
        }

        if (s->defer_accept > 0) {
                r = setsockopt_int(fd, SOL_TCP, TCP_DEFER_ACCEPT, s->defer_accept / USEC_PER_SEC);
                if (r < 0)
                        log_socket_option_errno(s, r, "TCP_DEFER_ACCEPT");
        }

        if (s->no_delay) {
                if (s->socket_protocol == IPPROTO_SCTP) {
                        r = setsockopt_int(fd, SOL_SCTP, SCTP_NODELAY, true);
                        if (r < 0)
                                log_socket_option_errno(s, r, "SCTP_NODELAY");
                } else {
                        r = setsockopt_int(fd, SOL_TCP, TCP_NODELAY, true);
                        if (r < 0)
                                log_socket_option_errno(s, r, "TCP_NODELAY");
                }
        }

        if (s->broadcast) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_BROADCAST, true);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_BROADCAST");
        }

        if (s->pass_cred) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_PASSCRED");
        }

        if (s->pass_pidfd) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSPIDFD, true);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_PASSPIDFD");
        }

        if (s->pass_sec) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSSEC, true);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_PASSSEC");
        }

        if (s->pass_pktinfo) {
                r = socket_set_recvpktinfo(fd, socket_address_family(&p->address), true);
                if (r < 0)
                        log_socket_option_errno(s, r, "packet info");
        }

        if (!s->pass_rights) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSRIGHTS, false);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_PASSRIGHTS");
        }

        if (s->timestamping != SOCKET_TIMESTAMPING_OFF) {
                r = setsockopt_int(fd, SOL_SOCKET,
                                   s->timestamping == SOCKET_TIMESTAMPING_NS ? SO_TIMESTAMPNS : SO_TIMESTAMP,
                                   true);
                if (r < 0)
                        log_socket_option_errno(s, r, "timestamping");
        }

        if (s->priority >= 0) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, s->priority);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_PRIORITY");
        }

        if (s->receive_buffer > 0) {
                r = fd_set_rcvbuf(fd, s->receive_buffer, false);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_RCVBUF/SO_RCVBUFFORCE");
        }

        if (s->send_buffer > 0) {
                r = fd_set_sndbuf(fd, s->send_buffer, false);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_SNDBUF/SO_SNDBUFFORCE");
        }

        if (s->mark >= 0) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_MARK, s->mark);
                if (r < 0)
                        log_socket_option_errno(s, r, "SO_MARK");
        }

        if (s->ip_tos >= 0) {
                r = setsockopt_int(fd, IPPROTO_IP, IP_TOS, s->ip_tos);
                if (r < 0)
                        log_socket_option_errno(s, r, "IP_TOS");
        }

        if (s->ip_ttl >= 0) {
                r = socket_set_ttl(fd, socket_address_family(&p->address), s->ip_ttl);
                if (r < 0)
                        log_socket_option_errno(s, r, "IP_TTL/IPV6_UNICAST_HOPS");
        }

        if (s->tcp_congestion)
                if (setsockopt(fd, SOL_TCP, TCP_CONGESTION, s->tcp_congestion, strlen(s->tcp_congestion)+1) < 0)
                        log_socket_option_errno(s, errno, "TCP_CONGESTION");

        if (s->smack_ip_in) {
                r = mac_smack_apply_fd(fd, SMACK_ATTR_IPIN, s->smack_ip_in);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "Failed to apply SMACK label for IP input, ignoring: %m");
        }

        if (s->smack_ip_out) {
                r = mac_smack_apply_fd(fd, SMACK_ATTR_IPOUT, s->smack_ip_out);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "Failed to apply SMACK label for IP output, ignoring: %m");
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

        _cleanup_close_ int fd = -EBADF;
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
        _cleanup_close_ int fd = -EBADF;
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

static int usbffs_address_create_at(int dfd, const char *name) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        assert(dfd >= 0);
        assert(name);

        fd = openat(dfd, name, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW);
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

        _cleanup_close_ int fd = -EBADF;
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
                        log_unit_warning_errno(UNIT(s), r, "Failed to create symlink %s %s %s, ignoring: %m",
                                               p, glyph(GLYPH_ARROW_RIGHT), *i);
        }

        return 0;
}

static int usbffs_write_descs(int fd, Service *s) {
        int r;

        assert(fd >= 0);
        assert(s);

        if (!s->usb_function_descriptors || !s->usb_function_strings)
                return -EINVAL;

        r = copy_file_fd(s->usb_function_descriptors, fd, 0);
        if (r < 0)
                return r;

        return copy_file_fd(s->usb_function_strings, fd, 0);
}

static int usbffs_dispatch_eps(SocketPort *p, int dfd) {
        _cleanup_free_ DirectoryEntries *des = NULL;
        int r;

        assert(p);
        assert(dfd >= 0);

        r = readdir_all(dfd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &des);
        if (r < 0)
                return r;

        p->auxiliary_fds = new(int, des->n_entries);
        if (!p->auxiliary_fds)
                return -ENOMEM;

        FOREACH_ARRAY(i, des->entries, des->n_entries) {
                const struct dirent *de = *i;

                if (streq(de->d_name, "ep0"))
                        continue;

                r = usbffs_address_create_at(dfd, de->d_name);
                if (r < 0)
                        goto fail;

                p->auxiliary_fds[p->n_auxiliary_fds++] = r;
        }

        assert(p->n_auxiliary_fds < des->n_entries);

        return 0;

fail:
        socket_port_close_auxiliary_fds(p);
        return r;
}

int socket_load_service_unit(Socket *s, int cfd, Unit **ret) {
        int r;

        /* Figure out what the unit that will be used to handle the connections on the socket looks like.
         *
         * If cfd < 0, then we don't have a connection yet. In case of Accept=yes sockets, use a fake
         * instance name.
         */

        assert(s);
        assert(ret);

        if (UNIT_ISSET(s->service)) {
                *ret = UNIT_DEREF(s->service);
                return 0;
        }

        if (!s->accept)
                return -ENODATA;

        /* Build the instance name and load the unit */
        _cleanup_free_ char *prefix = NULL, *instance = NULL, *name = NULL;

        r = unit_name_to_prefix(UNIT(s)->id, &prefix);
        if (r < 0)
                return r;

        if (cfd >= 0) {
                r = instance_from_socket(cfd, s->n_accepted, &instance);
                if (ERRNO_IS_NEG_DISCONNECT(r))
                        /* ENOTCONN is legitimate if TCP RST was received. Other socket families might return
                         * different errors. This connection is over, but the socket unit lives on. */
                        return log_unit_debug_errno(UNIT(s), r,
                                                    "Got error %s on incoming socket, assuming aborted connection attempt, ignoring.",
                                                    ERRNO_NAME(r));
                if (r < 0)
                        return r;
        }

        /* For accepting sockets, we don't know how the instance will be called until we get a connection and
         * can figure out what the peer name is. So let's use "internal" as the instance to make it clear
         * that this is not an actual peer name. We use "unknown" when we cannot figure out the peer. */
        r = unit_name_build(prefix, instance ?: "internal", ".service", &name);
        if (r < 0)
                return r;

        return manager_load_unit(UNIT(s)->manager, name, NULL, NULL, ret);
}

static int socket_determine_selinux_label(Socket *s, char **ret) {
        Unit *service;
        int r;

        assert(s);
        assert(ret);

        r = socket_load_service_unit(s, /* cfd= */ -EBADF, &service);
        if (r == -ENODATA) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        r = service_determine_exec_selinux_label(SERVICE(service), ret);
        if (r == -ENODATA) {
                *ret = NULL;
                return 0;
        }
        return r;
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

static bool fork_needed(const SocketAddress *address, Socket *s) {
        assert(address);
        assert(s);

        /* Check if we need to do the cgroup or netns stuff. If not we can do things much simpler. */

        /* If there are any NFTSet= directives with cgroup source, we need the cgroup */
        Unit *u = UNIT(s);
        CGroupContext *c = unit_get_cgroup_context(u);
        if (c)
                FOREACH_ARRAY(nft_set, c->nft_set_context.sets, c->nft_set_context.n_sets)
                        if (nft_set->source == NFT_SET_SOURCE_CGROUP)
                                return true;

        if (IN_SET(address->sockaddr.sa.sa_family, AF_INET, AF_INET6) &&
            bpf_program_supported() > 0) /* If BPF firewalling isn't supported anyway — there's no point in this forking complexity */
                return true;

        return exec_needs_network_namespace(&s->exec_context);
}

static int socket_address_listen_in_cgroup(
                Socket *s,
                const SocketAddress *address,
                const char *label) {

        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int fd, r;

        assert(s);
        assert(address);

        /* This is a wrapper around socket_address_listen(), that forks off a helper process inside the
         * socket's cgroup and network namespace in which the socket is actually created. This way we ensure
         * the socket is actually properly attached to the unit's cgroup for the purpose of BPF filtering and
         * such. */

        if (!fork_needed(address, s)) {
                /* Shortcut things... */
                fd = socket_address_listen_do(s, address, label);
                if (fd < 0)
                        return log_address_error_errno(UNIT(s), address, fd, "Failed to create listening socket (%s): %m");

                return fd;
        }

        r = unit_setup_exec_runtime(UNIT(s));
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to acquire runtime: %m");

        if (s->exec_context.network_namespace_path &&
            s->exec_runtime &&
            s->exec_runtime->shared &&
            s->exec_runtime->shared->netns_storage_socket[0] >= 0) {
                r = open_shareable_ns_path(s->exec_runtime->shared->netns_storage_socket, s->exec_context.network_namespace_path, CLONE_NEWNET);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to open network namespace path %s: %m", s->exec_context.network_namespace_path);
        }

        if (s->exec_context.ipc_namespace_path &&
            s->exec_runtime &&
            s->exec_runtime->shared &&
            s->exec_runtime->shared->ipcns_storage_socket[0] >= 0) {
                r = open_shareable_ns_path(s->exec_runtime->shared->ipcns_storage_socket, s->exec_context.ipc_namespace_path, CLONE_NEWIPC);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to open IPC namespace path %s: %m", s->exec_context.ipc_namespace_path);
        }

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) < 0)
                return log_unit_error_errno(UNIT(s), errno, "Failed to create communication channel: %m");

        r = unit_fork_helper_process(UNIT(s), "(sd-listen)", /* into_cgroup= */ true, &pid);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to fork off listener stub process: %m");
        if (r == 0) {
                /* Child */

                pair[0] = safe_close(pair[0]);

                if (exec_needs_network_namespace(&s->exec_context) &&
                    s->exec_runtime &&
                    s->exec_runtime->shared &&
                    s->exec_runtime->shared->netns_storage_socket[0] >= 0) {

                        if (namespace_type_supported(NAMESPACE_NET)) {
                                r = setup_shareable_ns(s->exec_runtime->shared->netns_storage_socket, CLONE_NEWNET);
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
        r = wait_for_terminate_and_check("(sd-listen)", pid.pid, WAIT_LOG_ABNORMAL);
        if (r < 0) {
                safe_close(fd);
                return r;
        }

        if (fd < 0)
                return log_address_error_errno(UNIT(s), address, fd, "Failed to receive listening socket (%s): %m");

        return fd;
}

static int socket_open_fds(Socket *orig_s) {
        _cleanup_(socket_close_fdsp) Socket *s = orig_s;
        _cleanup_freecon_ char *label = NULL;
        bool know_label = false;
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {

                if (p->fd >= 0)
                        continue;

                switch (p->type) {

                case SOCKET_SOCKET:

                        if (!know_label) {
                                /* Figure out the label, if we don't it know yet. We do it once for the first
                                 * socket where we need this and remember it for the rest. */

                                r = socket_determine_selinux_label(s, &label);
                                if (r < 0)
                                        return log_unit_error_errno(UNIT(s), r, "Failed to determine SELinux label: %m");

                                know_label = true;
                        }

                        /* Apply the socket protocol */
                        switch (p->address.type) {

                        case SOCK_STREAM:
                                if (IN_SET(s->socket_protocol, IPPROTO_SCTP, IPPROTO_MPTCP))
                                        p->address.protocol = s->socket_protocol;
                                break;

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

                        socket_apply_socket_options(s, p, p->fd);
                        socket_symlink(s);
                        break;

                case SOCKET_SPECIAL:

                        p->fd = special_address_create(p->path, s->writable);
                        if (p->fd < 0)
                                return log_unit_error_errno(UNIT(s), p->fd, "Failed to open special file '%s': %m", p->path);
                        break;

                case SOCKET_FIFO:

                        p->fd = fifo_address_create(
                                        p->path,
                                        s->directory_mode,
                                        s->socket_mode);
                        if (p->fd < 0)
                                return log_unit_error_errno(UNIT(s), p->fd, "Failed to open FIFO '%s': %m", p->path);

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
                                return log_unit_error_errno(UNIT(s), p->fd, "Failed to open message queue '%s': %m", p->path);
                        break;

                case SOCKET_USB_FUNCTION: {
                        _cleanup_close_ int dfd = -EBADF;

                        dfd = open(p->path, O_DIRECTORY|O_CLOEXEC);
                        if (dfd < 0)
                                return log_unit_error_errno(UNIT(s), errno,
                                                            "Failed to open USB FunctionFS dir '%s': %m", p->path);

                        p->fd = usbffs_address_create_at(dfd, "ep0");
                        if (p->fd < 0)
                                return log_unit_error_errno(UNIT(s), p->fd, "Failed to open USB FunctionFS ep0: %m");

                        r = usbffs_write_descs(p->fd, SERVICE(UNIT_DEREF(s->service)));
                        if (r < 0)
                                return log_unit_error_errno(UNIT(s), r, "Failed to write to USB FunctionFS ep0: %m");

                        r = usbffs_dispatch_eps(p, dfd);
                        if (r < 0)
                                return log_unit_error_errno(UNIT(s), r, "Failed to dispatch USB FunctionFS eps: %m");

                        break;
                }

                default:
                        assert_not_reached();
                }
        }

        TAKE_PTR(s);
        return 0;
}

static void socket_unwatch_fds(Socket *s) {
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                r = sd_event_source_set_enabled(p->event_source, SD_EVENT_OFF);
                if (r < 0)
                        log_unit_debug_errno(UNIT(s), r, "Failed to disable event source: %m");
        }
}

static int socket_watch_fds(Socket *s) {
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

                r = sd_event_source_set_ratelimit(p->event_source, s->poll_limit.interval, s->poll_limit.burst);
                if (r < 0)
                        log_unit_debug_errno(UNIT(s), r, "Failed to set poll limit on I/O event source, ignoring: %m");
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

        if (!SOCKET_STATE_WITH_PROCESS(state) && state != SOCKET_DEFERRED)
                s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);

        if (!SOCKET_STATE_WITH_PROCESS(state)) {
                socket_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SOCKET_EXEC_COMMAND_INVALID;
        }

        if (state != SOCKET_LISTENING)
                socket_unwatch_fds(s);

        if (!IN_SET(state,
                    SOCKET_START_OPEN,
                    SOCKET_START_CHOWN,
                    SOCKET_START_POST,
                    SOCKET_LISTENING,
                    SOCKET_DEFERRED,
                    SOCKET_RUNNING,
                    SOCKET_STOP_PRE,
                    SOCKET_STOP_PRE_SIGTERM,
                    SOCKET_STOP_PRE_SIGKILL))
                socket_close_fds(s);

        if (state != SOCKET_DEFERRED)
                unit_remove_from_stop_notify_queue(UNIT(s));

        if (state != old_state)
                log_unit_debug(UNIT(s), "Changed %s -> %s", socket_state_to_string(old_state), socket_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state], /* reload_success = */ true);
}

static int socket_coldplug(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        int r;

        assert(s->state == SOCKET_DEAD);

        if (s->deserialized_state == s->state)
                return 0;

        /* Patch "deferred" back to "listening" and let socket_enter_running() figure out what to do.
         * This saves us the trouble of handling flipping of DeferTrigger= vs Accept= during reload. */
        if (s->deserialized_state == SOCKET_DEFERRED)
                s->deserialized_state = SOCKET_LISTENING;

        if (pidref_is_set(&s->control_pid) &&
            pidref_is_unwaited(&s->control_pid) > 0 &&
            SOCKET_STATE_WITH_PROCESS(s->deserialized_state)) {

                r = unit_watch_pidref(UNIT(s), &s->control_pid, /* exclusive= */ false);
                if (r < 0)
                        return r;

                r = socket_arm_timer(s, /* relative= */ false, usec_add(u->state_change_timestamp.monotonic, s->timeout_usec));
                if (r < 0)
                        return r;
        }

        if (IN_SET(s->deserialized_state,
                   SOCKET_START_OPEN,
                   SOCKET_START_CHOWN,
                   SOCKET_START_POST,
                   SOCKET_LISTENING,
                   SOCKET_RUNNING)) {

                /* Originally, we used to simply reopen all sockets here that we didn't have file descriptors
                 * for. However, this is problematic, as we won't traverse through the SOCKET_START_CHOWN
                 * state for them, and thus the UID/GID wouldn't be right. Hence, instead simply check if we
                 * have all fds open, and if there's a mismatch, warn loudly.
                 *
                 * Note that SOCKET_START_OPEN requires no special treatment, as it's only intermediate
                 * between SOCKET_START_PRE and SOCKET_START_CHOWN and shall otherwise not be observed.
                 * It's listed only for consistency. */

                r = socket_check_open(s);
                if (r == SOCKET_OPEN_NONE)
                        log_unit_warning(UNIT(s),
                                         "Unit configuration changed while unit was running, "
                                         "and no socket file descriptors are open. "
                                         "Unit not functional until restarted.");
                else if (r == SOCKET_OPEN_SOME)
                        log_unit_warning(UNIT(s),
                                         "Unit configuration changed while unit was running, "
                                         "and some socket file descriptors have not been opened yet. "
                                         "Unit not fully functional until restarted.");
        }

        if (s->deserialized_state == SOCKET_LISTENING) {
                r = socket_watch_fds(s);
                if (r < 0)
                        return r;
        }

        if (!IN_SET(s->deserialized_state, SOCKET_DEAD, SOCKET_FAILED, SOCKET_CLEANING))
                (void) unit_setup_exec_runtime(u);

        socket_set_state(s, s->deserialized_state);
        return 0;
}

static int socket_spawn(Socket *s, ExecCommand *c, PidRef *ret_pid) {
        _cleanup_(exec_params_shallow_clear) ExecParameters exec_params = EXEC_PARAMETERS_INIT(
                        EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN);
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert(s);
        assert(c);
        assert(ret_pid);

        r = unit_prepare_exec(UNIT(s));
        if (r < 0)
                return r;

        r = socket_arm_timer(s, /* relative= */ true, s->timeout_usec);
        if (r < 0)
                return r;

        r = unit_set_exec_params(UNIT(s), &exec_params);
        if (r < 0)
                return r;

        /* Note that ExecStartPre= command doesn't inherit any FDs. It runs before we open listen FDs. */
        if (s->pass_fds_to_exec) {
                _cleanup_strv_free_ char **fd_names = NULL;
                _cleanup_free_ int *fds = NULL;
                int n_fds;

                n_fds = socket_collect_fds(s, &fds);
                if (n_fds < 0)
                        return n_fds;

                r = strv_extend_n(&fd_names, socket_fdname(s), n_fds);
                if (r < 0)
                        return r;

                exec_params.flags |= EXEC_PASS_FDS;
                exec_params.fds = TAKE_PTR(fds);
                exec_params.fd_names = TAKE_PTR(fd_names);
                exec_params.n_socket_fds = n_fds;
        }

        r = exec_spawn(UNIT(s),
                       c,
                       &s->exec_context,
                       &exec_params,
                       s->exec_runtime,
                       &s->cgroup_context,
                       &pidref);
        if (r < 0)
                return r;

        r = unit_watch_pidref(UNIT(s), &pidref, /* exclusive= */ true);
        if (r < 0)
                return r;

        *ret_pid = TAKE_PIDREF(pidref);
        return 0;
}

static int socket_chown(Socket *s, PidRef *ret_pid) {
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        int r;

        assert(s);

        r = socket_arm_timer(s, /* relative= */ true, s->timeout_usec);
        if (r < 0)
                return r;

        /* We have to resolve the user names out-of-process, hence
         * let's fork here. It's messy, but well, what can we do? */

        r = unit_fork_helper_process(UNIT(s), "(sd-chown)", /* into_cgroup= */ true, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                uid_t uid = UID_INVALID;
                gid_t gid = GID_INVALID;

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
                        else if (p->type == SOCKET_MQUEUE) {
                                /* Use fchown on the fd since /dev/mqueue might not be mounted. */
                                if (fchown(p->fd, uid, gid) < 0) {
                                        log_unit_error_errno(UNIT(s), errno, "Failed to fchown(): %m");
                                        _exit(EXIT_CHOWN);
                                }
                                continue;
                        }

                        if (!path)
                                continue;

                        if (chown(path, uid, gid) < 0) {
                                log_unit_error_errno(UNIT(s), errno, "Failed to chown(): %m");
                                _exit(EXIT_CHOWN);
                        }
                }

                _exit(EXIT_SUCCESS);
        }

        r = unit_watch_pidref(UNIT(s), &pid, /* exclusive= */ true);
        if (r < 0)
                return r;

        *ret_pid = TAKE_PIDREF(pid);
        return 0;
}

static void socket_enter_dead(Socket *s, SocketResult f) {
        assert(s);

        if (s->result == SOCKET_SUCCESS)
                s->result = f;

        if (s->result == SOCKET_SUCCESS)
                unit_log_success(UNIT(s));
        else
                unit_log_failure(UNIT(s), socket_result_to_string(s->result));

        unit_warn_leftover_processes(UNIT(s), /* start = */ false);

        socket_set_state(s, s->result != SOCKET_SUCCESS ? SOCKET_FAILED : SOCKET_DEAD);

        s->exec_runtime = exec_runtime_destroy(s->exec_runtime);

        unit_destroy_runtime_data(UNIT(s), &s->exec_context, /* destroy_runtime_dir = */ true);

        unit_unref_uid_gid(UNIT(s), true);
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
                pidref_done(&s->control_pid);

                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'stop-post' task: %m");
                        socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_FAILURE_RESOURCES);
                        return;
                }

                socket_set_state(s, SOCKET_STOP_POST);
        } else
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_SUCCESS);
}

static int state_to_kill_operation(Socket *s, SocketState state) {
        assert(s);

        if (state == SOCKET_STOP_PRE_SIGTERM)
                return unit_has_job_type(UNIT(s), JOB_RESTART) ? KILL_RESTART : KILL_TERMINATE;

        if (state == SOCKET_FINAL_SIGTERM)
                return KILL_TERMINATE;

        return KILL_KILL;
}

static void socket_enter_signal(Socket *s, SocketState state, SocketResult f) {
        int r;

        assert(s);

        if (s->result == SOCKET_SUCCESS)
                s->result = f;

        r = unit_kill_context(UNIT(s), state_to_kill_operation(s, state));
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");
                goto fail;
        }
        if (r > 0) {
                r = socket_arm_timer(s, /* relative= */ true, s->timeout_usec);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                        goto fail;
                }

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
                pidref_done(&s->control_pid);

                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'stop-pre' task: %m");
                        socket_enter_stop_post(s, SOCKET_FAILURE_RESOURCES);
                        return;
                }

                socket_set_state(s, SOCKET_STOP_PRE);
        } else
                socket_enter_stop_post(s, SOCKET_SUCCESS);
}

static void flush_ports(Socket *s) {
        assert(s);

        /* Flush all incoming traffic, regardless if actual bytes or new connections, so that this socket isn't busy
         * anymore */

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                if (p->type == SOCKET_MQUEUE)
                        (void) flush_mqueue(p->fd);
                else {
                        (void) flush_accept(p->fd);
                        (void) flush_fd(p->fd);
                }
        }
}

static void socket_enter_listening(Socket *s) {
        int r;

        assert(s);

        if (!s->accept && s->flush_pending) {
                log_unit_debug(UNIT(s), "Flushing socket before listening.");
                flush_ports(s);
        }

        r = socket_watch_fds(s);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to watch sockets: %m");
                socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
                return;
        }

        socket_set_state(s, SOCKET_LISTENING);
}

static void socket_enter_start_post(Socket *s) {
        int r;

        assert(s);

        socket_unwatch_control_pid(s);
        s->control_command_id = SOCKET_EXEC_START_POST;
        s->control_command = s->exec_command[SOCKET_EXEC_START_POST];

        if (s->control_command) {
                pidref_done(&s->control_pid);

                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'start-post' task: %m");
                        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
                        return;
                }

                socket_set_state(s, SOCKET_START_POST);
        } else
                socket_enter_listening(s);
}

static void socket_enter_start_chown(Socket *s) {
        int r;

        assert(s);
        assert(s->state == SOCKET_START_OPEN);

        if (!isempty(s->user) || !isempty(s->group)) {

                socket_unwatch_control_pid(s);
                s->control_command_id = SOCKET_EXEC_START_CHOWN;
                s->control_command = NULL;

                r = socket_chown(s, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'start-chown' task: %m");
                        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
                        return;
                }

                socket_set_state(s, SOCKET_START_CHOWN);
        } else
                socket_enter_start_post(s);
}

static void socket_enter_start_open(Socket *s) {
        int r;

        assert(s);
        assert(IN_SET(s->state, SOCKET_DEAD, SOCKET_FAILED, SOCKET_START_PRE));

        /* We force a state transition here even though we're not spawning any process (i.e. the state is purely
         * intermediate), so that failure of socket_open_fds() always causes a state change in unit_notify().
         * Otherwise, if no Exec*= is defined, we might go from previous SOCKET_FAILED to SOCKET_FAILED,
         * meaning the OnFailure= deps are unexpectedly skipped (#35635). */

        socket_set_state(s, SOCKET_START_OPEN);

        r = socket_open_fds(s);
        if (r < 0) {
                log_unit_error_errno(UNIT(s), r, "Failed to listen on sockets: %m");
                socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
                return;
        }

        socket_enter_start_chown(s);
}

static void socket_enter_start_pre(Socket *s) {
        int r;

        assert(s);

        socket_unwatch_control_pid(s);

        unit_warn_leftover_processes(UNIT(s), /* start = */ true);

        s->control_command_id = SOCKET_EXEC_START_PRE;
        s->control_command = s->exec_command[SOCKET_EXEC_START_PRE];

        if (s->control_command) {
                pidref_done(&s->control_pid);

                r = socket_spawn(s, s->control_command, &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'start-pre' task: %m");
                        socket_enter_dead(s, SOCKET_FAILURE_RESOURCES);
                        return;
                }

                socket_set_state(s, SOCKET_START_PRE);
        } else
                socket_enter_start_open(s);
}

static bool socket_may_defer(Socket *s) {
        assert(s);

        switch (s->defer_trigger) {

        case SOCKET_DEFER_NO:
                return false;

        case SOCKET_DEFER_YES:
                return !hashmap_isempty(UNIT(s)->manager->jobs);

        case SOCKET_DEFER_PATIENT:
                assert(s->defer_trigger_max_usec > 0);
                return true;

        default:
                assert_not_reached();
        }
}

static bool socket_stop_notify(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s->state == SOCKET_DEFERRED);

        r = manager_add_job(u->manager, JOB_START, UNIT_DEREF(s->service), JOB_LENIENT, &error, /* ret = */ NULL);
        if (r >= 0) { /* Yay! */
                socket_set_state(s, SOCKET_RUNNING);
                return true; /* changed */
        }
        if (sd_bus_error_has_name(&error, BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE)) {
                if (s->defer_trigger == SOCKET_DEFER_PATIENT || !hashmap_isempty(u->manager->jobs))
                        /* Wait for some more */
                        return false;

                log_unit_warning_errno(u, r, "Service conflicts with active units even after all jobs have completed, giving up.");
        } else
                log_unit_warning_errno(u, r, "Failed to queue service startup job: %s", bus_error_message(&error, r));

        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
        return true; /* changed */
}

static void socket_enter_deferred(Socket *s) {
        int r;

        assert(s);
        assert(socket_may_defer(s));

        /* So here's the thing: if there're currently units conflicting with the service we shall be
         * triggering, and the previous transaction is still running (job pool is not empty), let's
         * defer the activation a bit, and recheck upon any unit stop. IOW, the trigger in question
         * becomes bound to the conflicting dependency, and not the socket IO because we never process them.
         * Put a safety net around all this though, i.e. give up if the service still can't be started
         * even after all existing jobs have completed, or DeferTriggerMaxSec= is reached. */

        r = socket_arm_timer(s, /* relative = */ true, s->defer_trigger_max_usec);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                return socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
        }

        unit_add_to_stop_notify_queue(UNIT(s));

        /* Disable IO event sources */
        socket_set_state(s, SOCKET_DEFERRED);
}

static void socket_enter_running(Socket *s, int cfd_in) {
        /* Note that this call takes possession of the connection fd passed. It either has to assign it
         * somewhere or close it. */
        _cleanup_close_ int cfd = cfd_in;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s);

        /* We don't take connections anymore if we are supposed to shut down anyway */
        if (unit_stop_pending(UNIT(s))) {

                log_unit_debug(UNIT(s), "Suppressing connection request since unit stop is scheduled.");

                if (cfd >= 0)
                        goto refuse;

                flush_ports(s);
                return;
        }

        if (s->state == SOCKET_DEFERRED) {
                assert(cfd < 0);
                return;
        }

        if (!ratelimit_below(&s->trigger_limit)) {
                log_unit_warning(UNIT(s), "Trigger limit hit, refusing further activation.");
                socket_enter_stop_pre(s, SOCKET_FAILURE_TRIGGER_LIMIT_HIT);
                goto refuse;
        }

        if (cfd < 0) { /* Accept=no case */
                bool pending = false;
                Unit *other;

                /* If there's already a start pending don't bother to do anything */
                UNIT_FOREACH_DEPENDENCY(other, UNIT(s), UNIT_ATOM_TRIGGERS)
                        if (unit_active_or_pending(other)) {
                                pending = true;
                                break;
                        }

                if (!pending) {
                        if (!UNIT_ISSET(s->service)) {
                                log_unit_warning(UNIT(s),
                                                 "Service to activate vanished, refusing activation.");
                                goto fail;
                        }

                        if (s->defer_trigger != SOCKET_DEFER_NO) {
                                r = manager_add_job(UNIT(s)->manager, JOB_START, UNIT_DEREF(s->service), JOB_LENIENT, &error, /* ret = */ NULL);
                                if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE) && socket_may_defer(s))
                                        /* We only check BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE here, not
                                         * BUS_ERROR_TRANSACTION_JOBS_CONFLICTING or BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC,
                                         * since those are errors in a single transaction, which are most likely
                                         * caused by dependency issues in the unit configuration.
                                         * Deferring activation probably won't help. */
                                        return socket_enter_deferred(s);
                        } else
                                r = manager_add_job(UNIT(s)->manager, JOB_START, UNIT_DEREF(s->service), JOB_REPLACE, &error, /* ret = */ NULL);
                        if (r < 0)
                                goto queue_error;
                }

                socket_set_state(s, SOCKET_RUNNING);
        } else { /* Accept=yes case */
                _cleanup_(socket_peer_unrefp) SocketPeer *p = NULL;
                Unit *service;

                if (s->n_connections >= s->max_connections) {
                        log_unit_warning(UNIT(s), "Too many incoming connections (%u), dropping connection.",
                                         s->n_connections);
                        goto refuse;
                }

                if (s->max_connections_per_source > 0) {
                        r = socket_acquire_peer(s, cfd, &p);
                        if (ERRNO_IS_NEG_DISCONNECT(r))
                                return;
                        if (r < 0)
                                /* We didn't have enough resources to acquire peer information, let's fail. */
                                goto fail;
                        if (r > 0 && p->n_ref > s->max_connections_per_source) {
                                _cleanup_free_ char *t = NULL;

                                if (p->peer.sa.sa_family == AF_UNIX)
                                        (void) asprintf(&t, "UID " UID_FMT, p->peer_cred.uid);
                                else
                                        (void) sockaddr_pretty(&p->peer.sa, p->peer_salen, /* translate_ipv6= */ true, /* include_port= */ false, &t);

                                log_unit_warning(UNIT(s),
                                                 "Too many incoming connections (%u) from source %s, dropping connection.",
                                                 p->n_ref, strnull(t));
                                goto refuse;
                        }
                }

                r = socket_load_service_unit(s, cfd, &service);
                if (ERRNO_IS_NEG_DISCONNECT(r))
                        return;
                if (r < 0 || UNIT_IS_LOAD_ERROR(service->load_state)) {
                        log_unit_warning_errno(UNIT(s), r < 0 ? r : service->load_error,
                                               "Failed to load connection service unit: %m");
                        goto fail;
                }
                if (service->load_state == UNIT_MASKED) {
                        log_unit_warning(UNIT(s), "Connection service unit is masked, refusing.");
                        goto fail;
                }

                s->n_accepted++;

                r = service_set_socket_fd(SERVICE(service), cfd, s, p, s->selinux_context_from_net);
                if (ERRNO_IS_NEG_DISCONNECT(r))
                        return;
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to set socket on service: %m");
                        goto fail;
                }

                /* We passed ownership of the fd and socket peer to the service now. */
                TAKE_FD(cfd);
                TAKE_PTR(p);

                s->n_connections++;

                r = manager_add_job(UNIT(s)->manager, JOB_START, service, JOB_REPLACE, &error, /* ret = */ NULL);
                if (r < 0) {
                        /* We failed to activate the new service, but it still exists. Let's make sure the
                         * service closes and forgets the connection fd again, immediately. */
                        service_release_socket_fd(SERVICE(service));
                        goto queue_error;
                }

                /* Notify clients about changed counters */
                unit_add_to_dbus_queue(UNIT(s));
        }

        return;

refuse:
        s->n_refused++;
        return;

queue_error:
        log_unit_warning_errno(UNIT(s), r, "Failed to queue service startup job%s: %s",
                               cfd >= 0 && !ERRNO_IS_RESOURCE(r) ? " (Maybe the service is missing or is a template unit?)" : "",
                               bus_error_message(&error, r));

fail:
        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
}

static void socket_run_next(Socket *s) {
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        socket_unwatch_control_pid(s);

        s->control_command = s->control_command->command_next;

        pidref_done(&s->control_pid);

        r = socket_spawn(s, s->control_command, &s->control_pid);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to spawn next task: %m");

                if (s->state == SOCKET_START_POST)
                        socket_enter_stop_pre(s, SOCKET_FAILURE_RESOURCES);
                else if (s->state == SOCKET_STOP_POST)
                        socket_enter_dead(s, SOCKET_FAILURE_RESOURCES);
                else
                        socket_enter_signal(s, SOCKET_FINAL_SIGTERM, SOCKET_FAILURE_RESOURCES);
        }
}

static int socket_start(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        int r;

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
                   SOCKET_START_OPEN,
                   SOCKET_START_CHOWN,
                   SOCKET_START_POST))
                return 0;

        /* Cannot run this without the service being around */
        if (UNIT_ISSET(s->service)) {
                Service *service = ASSERT_PTR(SERVICE(UNIT_DEREF(s->service)));

                if (UNIT(service)->load_state != UNIT_LOADED)
                        return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOENT),
                                                    "Socket service %s not loaded, refusing.", UNIT(service)->id);

                /* If the service is already active we cannot start the socket */
                if (SOCKET_SERVICE_IS_ACTIVE(service, /* allow_finalize = */ false))
                        return log_unit_error_errno(u, SYNTHETIC_ERRNO(EBUSY),
                                                    "Socket service %s already active, refusing.", UNIT(service)->id);
        }

        assert(IN_SET(s->state, SOCKET_DEAD, SOCKET_FAILED));

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        s->result = SOCKET_SUCCESS;
        exec_command_reset_status_list_array(s->exec_command, _SOCKET_EXEC_COMMAND_MAX);

        if (s->cgroup_runtime)
                s->cgroup_runtime->reset_accounting = true;

        socket_enter_start_pre(s);
        return 1;
}

static int socket_stop(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));

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
                   SOCKET_START_OPEN,
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

        assert(IN_SET(s->state, SOCKET_LISTENING, SOCKET_DEFERRED, SOCKET_RUNNING));

        socket_enter_stop_pre(s, SOCKET_SUCCESS);
        return 1;
}

static int socket_serialize(Unit *u, FILE *f, FDSet *fds) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        int r;

        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", socket_state_to_string(s->state));
        (void) serialize_item(f, "result", socket_result_to_string(s->result));
        (void) serialize_item_format(f, "n-accepted", "%u", s->n_accepted);
        (void) serialize_item_format(f, "n-refused", "%u", s->n_refused);
        (void) serialize_pidref(f, fds, "control-pid", &s->control_pid);

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

        (void) serialize_ratelimit(f, "trigger-ratelimit", &s->trigger_limit);

        return 0;
}

static int socket_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        int r;

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

                if (!pidref_is_set(&s->control_pid))
                        (void) deserialize_pidref(fds, value, &s->control_pid);

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
                _cleanup_free_ char *fdv = NULL;
                bool found = false;
                int fd;

                r = extract_first_word(&value, &fdv, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse fifo value: %s", value);
                        return 0;
                }

                fd = parse_fd(fdv);
                if (fd < 0 || !fdset_contains(fds, fd)) {
                        log_unit_debug(u, "Invalid fifo value: %s", fdv);
                        return 0;
                }

                LIST_FOREACH(port, p, s->ports)
                        if (p->fd < 0 &&
                            p->type == SOCKET_FIFO &&
                            path_equal_or_inode_same(p->path, value, 0)) {
                                p->fd = fdset_remove(fds, fd);
                                found = true;
                                break;
                        }
                if (!found)
                        log_unit_debug(u, "No matching fifo socket found: %s", value);

        } else if (streq(key, "special")) {
                _cleanup_free_ char *fdv = NULL;
                bool found = false;
                int fd;

                r = extract_first_word(&value, &fdv, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse special value: %s", value);
                        return 0;
                }

                fd = parse_fd(fdv);
                if (fd < 0 || !fdset_contains(fds, fd)) {
                        log_unit_debug(u, "Invalid special value: %s", fdv);
                        return 0;
                }

                LIST_FOREACH(port, p, s->ports)
                        if (p->fd < 0 &&
                            p->type == SOCKET_SPECIAL &&
                            path_equal_or_inode_same(p->path, value, 0)) {
                                p->fd = fdset_remove(fds, fd);
                                found = true;
                                break;
                        }
                if (!found)
                        log_unit_debug(u, "No matching special socket found: %s", value);

        } else if (streq(key, "mqueue")) {
                _cleanup_free_ char *fdv = NULL;
                bool found = false;
                int fd;

                r = extract_first_word(&value, &fdv, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse mqueue value: %s", value);
                        return 0;
                }

                fd = parse_fd(fdv);
                if (fd < 0 || !fdset_contains(fds, fd)) {
                        log_unit_debug(u, "Invalid mqueue value: %s", fdv);
                        return 0;
                }

                LIST_FOREACH(port, p, s->ports)
                        if (p->fd < 0 &&
                            p->type == SOCKET_MQUEUE &&
                            streq(p->path, value)) {
                                p->fd = fdset_remove(fds, fd);
                                found = true;
                                break;
                        }
                if (!found)
                        log_unit_debug(u, "No matching mqueue socket found: %s", value);

        } else if (streq(key, "socket")) {
                _cleanup_free_ char *fdv = NULL, *typev = NULL;
                bool found = false;
                int fd, type;

                r = extract_first_word(&value, &fdv, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse socket fd from value: %s", value);
                        return 0;
                }

                fd = parse_fd(fdv);
                if (fd < 0 || !fdset_contains(fds, fd)) {
                        log_unit_debug(u, "Invalid socket fd: %s", fdv);
                        return 0;
                }

                r = extract_first_word(&value, &typev, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse socket type from value: %s", value);
                        return 0;
                }

                if (safe_atoi(typev, &type) < 0 || type < 0) {
                        log_unit_debug(u, "Invalid socket type: %s", typev);
                        return 0;
                }

                LIST_FOREACH(port, p, s->ports)
                        if (p->fd < 0 &&
                            socket_address_is(&p->address, value, type)) {
                                p->fd = fdset_remove(fds, fd);
                                found = true;
                                break;
                        }
                if (!found)
                        log_unit_debug(u, "No matching %s socket found: %s",
                                       socket_address_type_to_string(type), value);

        } else if (streq(key, "netlink")) {
                _cleanup_free_ char *fdv = NULL;
                bool found = false;
                int fd;

                r = extract_first_word(&value, &fdv, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse socket value: %s", value);
                        return 0;
                }

                fd = parse_fd(fdv);
                if (fd < 0 || !fdset_contains(fds, fd)) {
                        log_unit_debug(u, "Invalid socket value: %s", fdv);
                        return 0;
                }

                LIST_FOREACH(port, p, s->ports)
                        if (p->fd < 0 &&
                            socket_address_is_netlink(&p->address, value)) {
                                p->fd = fdset_remove(fds, fd);
                                found = true;
                                break;
                        }
                if (!found)
                        log_unit_debug(u, "No matching netlink socket found: %s", value);

        } else if (streq(key, "ffs")) {
                _cleanup_free_ char *fdv = NULL;
                bool found = false;
                int fd;

                r = extract_first_word(&value, &fdv, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse ffs value: %s", value);
                        return 0;
                }

                fd = parse_fd(fdv);
                if (fd < 0 || !fdset_contains(fds, fd)) {
                        log_unit_debug(u, "Invalid ffs value: %s", fdv);
                        return 0;
                }

                LIST_FOREACH(port, p, s->ports)
                        if (p->fd < 0 &&
                            p->type == SOCKET_USB_FUNCTION &&
                            path_equal_or_inode_same(p->path, value, 0)) {
                                p->fd = fdset_remove(fds, fd);
                                found = true;
                                break;
                        }
                if (!found)
                        log_unit_debug(u, "No matching ffs socket found: %s", value);

        } else if (streq(key, "trigger-ratelimit"))
                (void) deserialize_ratelimit(&s->trigger_limit, key, value);
        else
                log_unit_debug(UNIT(s), "Unknown serialization key: %s", key);

        return 0;
}

static void socket_distribute_fds(Unit *u, FDSet *fds) {
        Socket *s = ASSERT_PTR(SOCKET(u));

        LIST_FOREACH(port, p, s->ports) {
                int fd;

                if (p->type != SOCKET_SOCKET)
                        continue;

                if (p->fd >= 0)
                        continue;

                FDSET_FOREACH(fd, fds) {
                        if (socket_address_matches_fd(&p->address, fd)) {
                                p->fd = fdset_remove(fds, fd);
                                s->deserialized_state = SOCKET_LISTENING;
                                break;
                        }
                }
        }
}

static UnitActiveState socket_active_state(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));

        return state_translation_table[s->state];
}

static const char *socket_sub_state_to_string(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));

        return socket_state_to_string(s->state);
}

int socket_port_to_address(const SocketPort *p, char **ret) {
        _cleanup_free_ char *address = NULL;
        int r;

        assert(p);
        assert(ret);

        switch (p->type) {
                case SOCKET_SOCKET: {
                        r = socket_address_print(&p->address, &address);
                        if (r < 0)
                                return r;

                        break;
                }

                case SOCKET_SPECIAL:
                case SOCKET_MQUEUE:
                case SOCKET_FIFO:
                case SOCKET_USB_FUNCTION:
                        address = strdup(p->path);
                        if (!address)
                                return -ENOMEM;
                        break;

                default:
                        assert_not_reached();
        }

        *ret = TAKE_PTR(address);

        return 0;
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

static bool socket_may_gc(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));

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
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int cfd, r;

        assert(s);
        assert(p);
        assert(fd >= 0);

        /* Similar to socket_address_listen_in_cgroup(), but for accept() rather than socket(): make sure that any
         * connection socket is also properly associated with the cgroup. */

        if (!IN_SET(p->address.sockaddr.sa.sa_family, AF_INET, AF_INET6))
                goto shortcut;

        if (bpf_program_supported() <= 0)
                goto shortcut;

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) < 0)
                return log_unit_error_errno(UNIT(s), errno, "Failed to create communication channel: %m");

        r = unit_fork_helper_process(UNIT(s), "(sd-accept)", /* into_cgroup= */ true, &pid);
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
        r = wait_for_terminate_and_check("(sd-accept)", pid.pid, WAIT_LOG_ABNORMAL);
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
        SocketPort *p = ASSERT_PTR(userdata);
        int cfd = -EBADF;

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

                socket_apply_socket_options(p->socket, p, cfd);
        }

        socket_enter_running(p->socket, cfd);
        return 0;

fail:
        socket_enter_stop_pre(p->socket, SOCKET_FAILURE_RESOURCES);
        return 0;
}

static void socket_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        SocketResult f;

        assert(pid >= 0);

        if (pid != s->control_pid.pid)
                return;

        pidref_done(&s->control_pid);

        if (is_clean_exit(code, status, EXIT_CLEAN_COMMAND, NULL))
                f = SOCKET_SUCCESS;
        else if (code == CLD_EXITED)
                f = SOCKET_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = SOCKET_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = SOCKET_FAILURE_CORE_DUMP;
        else
                assert_not_reached();

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
                                socket_enter_start_open(s);
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
                        assert_not_reached();
                }
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);
}

static int socket_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Socket *s = ASSERT_PTR(SOCKET(userdata));

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

        case SOCKET_DEFERRED:
                log_unit_warning(UNIT(s), "DeferTriggerMaxSec= elapsed. Stopping.");
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
                assert_not_reached();
        }

        return 0;
}

int socket_collect_fds(Socket *s, int **ret) {
        size_t n = 0, k = 0;

        assert(s);
        assert(ret);

        /* Called from the service code for requesting our fds */

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd >= 0)
                        n++;
                n += p->n_auxiliary_fds;
        }

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        int *fds = new(int, n);
        if (!fds)
                return -ENOMEM;

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd >= 0)
                        fds[k++] = p->fd;
                FOREACH_ARRAY(i, p->auxiliary_fds, p->n_auxiliary_fds)
                        fds[k++] = *i;
        }

        assert(k == n);

        *ret = fds;
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
        Socket *s = ASSERT_PTR(SOCKET(u));

        assert(other);

        /* Filter out invocations with bogus state */
        assert(UNIT_IS_LOAD_COMPLETE(other->load_state));

        Service *service = ASSERT_PTR(SERVICE(other));

        /* Don't propagate state changes from the service if we are already down */
        if (!IN_SET(s->state, SOCKET_RUNNING, SOCKET_LISTENING, SOCKET_DEFERRED))
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

        if (!SOCKET_SERVICE_IS_ACTIVE(service, /* allow_finalize = */ true))
                socket_enter_listening(s);

        if (SERVICE(other)->state == SERVICE_RUNNING)
                socket_set_state(s, SOCKET_RUNNING);
}

static void socket_handoff_timestamp(
                Unit *u,
                const struct ucred *ucred,
                const dual_timestamp *ts) {

        Socket *s = ASSERT_PTR(SOCKET(u));

        assert(ucred);
        assert(ts);

        if (s->control_pid.pid == ucred->pid && s->control_command) {
                exec_status_handoff(&s->control_command->exec_status, ucred, ts);
                unit_add_to_dbus_queue(u);
        }
}

static int socket_get_timeout(Unit *u, usec_t *timeout) {
        Socket *s = ASSERT_PTR(SOCKET(u));
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

const char* socket_fdname(Socket *s) {
        assert(s);

        /* Returns the name to use for $LISTEN_FDNAMES. If the user didn't specify anything specifically,
         * use the socket unit's name as fallback for Accept=no sockets, "connection" otherwise. */

        if (s->fdname)
                return s->fdname;

        if (s->accept)
                return "connection";

        return UNIT(s)->id;
}

static PidRef* socket_control_pid(Unit *u) {
        return &ASSERT_PTR(SOCKET(u))->control_pid;
}

static int socket_clean(Unit *u, ExecCleanMask mask) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        _cleanup_strv_free_ char **l = NULL;
        int r;

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

        r = socket_arm_timer(s, /* relative= */ true, s->exec_context.timeout_clean_usec);
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to install timer: %m");
                goto fail;
        }

        r = unit_fork_and_watch_rm_rf(u, l, &s->control_pid);
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to spawn cleaning task: %m");
                goto fail;
        }

        socket_set_state(s, SOCKET_CLEANING);
        return 0;

fail:
        s->clean_result = SOCKET_FAILURE_RESOURCES;
        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
        return r;
}

static int socket_can_clean(Unit *u, ExecCleanMask *ret) {
        Socket *s = ASSERT_PTR(SOCKET(u));

        return exec_context_get_clean_mask(&s->exec_context, ret);
}

static int socket_can_start(Unit *u) {
        Socket *s = ASSERT_PTR(SOCKET(u));
        int r;

        r = unit_test_start_limit(u);
        if (r < 0) {
                socket_enter_dead(s, SOCKET_FAILURE_START_LIMIT_HIT);
                return r;
        }

        return 1;
}

static const char* const socket_exec_command_table[_SOCKET_EXEC_COMMAND_MAX] = {
        [SOCKET_EXEC_START_PRE]   = "ExecStartPre",
        [SOCKET_EXEC_START_CHOWN] = "ExecStartChown",
        [SOCKET_EXEC_START_POST]  = "ExecStartPost",
        [SOCKET_EXEC_STOP_PRE]    = "ExecStopPre",
        [SOCKET_EXEC_STOP_POST]   = "ExecStopPost",
};

DEFINE_STRING_TABLE_LOOKUP(socket_exec_command, SocketExecCommand);

static const char* const socket_result_table[_SOCKET_RESULT_MAX] = {
        [SOCKET_SUCCESS]                         = "success",
        [SOCKET_FAILURE_RESOURCES]               = "resources",
        [SOCKET_FAILURE_TIMEOUT]                 = "timeout",
        [SOCKET_FAILURE_EXIT_CODE]               = "exit-code",
        [SOCKET_FAILURE_SIGNAL]                  = "signal",
        [SOCKET_FAILURE_CORE_DUMP]               = "core-dump",
        [SOCKET_FAILURE_START_LIMIT_HIT]         = "start-limit-hit",
        [SOCKET_FAILURE_TRIGGER_LIMIT_HIT]       = "trigger-limit-hit",
        [SOCKET_FAILURE_SERVICE_START_LIMIT_HIT] = "service-start-limit-hit",
};

DEFINE_STRING_TABLE_LOOKUP(socket_result, SocketResult);

static const char* const socket_timestamping_table[_SOCKET_TIMESTAMPING_MAX] = {
        [SOCKET_TIMESTAMPING_OFF] = "off",
        [SOCKET_TIMESTAMPING_US]  = "us",
        [SOCKET_TIMESTAMPING_NS]  = "ns",
};

DEFINE_STRING_TABLE_LOOKUP(socket_timestamping, SocketTimestamping);

SocketTimestamping socket_timestamping_from_string_harder(const char *p) {
        SocketTimestamping t;
        int r;

        if (!p)
                return _SOCKET_TIMESTAMPING_INVALID;

        t = socket_timestamping_from_string(p);
        if (t >= 0)
                return t;

        /* Let's alternatively support the various other aliases parse_time() accepts for ns and µs here,
         * too. */
        if (streq(p, "nsec"))
                return SOCKET_TIMESTAMPING_NS;
        if (STR_IN_SET(p, "usec", "µs", "μs")) /* Accept both small greek letter mu + micro sign unicode codepoints */
                return SOCKET_TIMESTAMPING_US;

        r = parse_boolean(p);
        if (r < 0)
                return _SOCKET_TIMESTAMPING_INVALID;

        return r ? SOCKET_TIMESTAMPING_NS : SOCKET_TIMESTAMPING_OFF; /* If boolean yes, default to ns accuracy */
}

static const char* const socket_defer_trigger_table[_SOCKET_DEFER_MAX] = {
        [SOCKET_DEFER_NO]      = "no",
        [SOCKET_DEFER_YES]     = "yes",
        [SOCKET_DEFER_PATIENT] = "patient",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(socket_defer_trigger, SocketDeferTrigger, SOCKET_DEFER_YES);

const UnitVTable socket_vtable = {
        .object_size = sizeof(Socket),
        .exec_context_offset = offsetof(Socket, exec_context),
        .cgroup_context_offset = offsetof(Socket, cgroup_context),
        .kill_context_offset = offsetof(Socket, kill_context),
        .exec_runtime_offset = offsetof(Socket, exec_runtime),
        .cgroup_runtime_offset = offsetof(Socket, cgroup_runtime),

        .sections =
                "Unit\0"
                "Socket\0"
                "Install\0",
        .private_section = "Socket",

        .can_transient = true,
        .can_trigger = true,
        .can_fail = true,

        .init = socket_init,
        .done = socket_done,
        .load = socket_load,

        .coldplug = socket_coldplug,

        .dump = socket_dump,

        .start = socket_start,
        .stop = socket_stop,

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

        .stop_notify = socket_stop_notify,

        .reset_failed = socket_reset_failed,

        .notify_handoff_timestamp = socket_handoff_timestamp,

        .control_pid = socket_control_pid,

        .bus_set_property = bus_socket_set_property,
        .bus_commit_properties = bus_socket_commit_properties,

        .status_message_formats = {
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

        .can_start = socket_can_start,
};
