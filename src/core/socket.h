/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Socket Socket;
typedef struct SocketPeer SocketPeer;

#include "mount.h"
#include "pidref.h"
#include "socket-util.h"
#include "unit.h"

typedef enum SocketExecCommand {
        SOCKET_EXEC_START_PRE,
        SOCKET_EXEC_START_CHOWN,
        SOCKET_EXEC_START_POST,
        SOCKET_EXEC_STOP_PRE,
        SOCKET_EXEC_STOP_POST,
        _SOCKET_EXEC_COMMAND_MAX,
        _SOCKET_EXEC_COMMAND_INVALID = -EINVAL,
} SocketExecCommand;

typedef enum SocketType {
        SOCKET_SOCKET,
        SOCKET_FIFO,
        SOCKET_SPECIAL,
        SOCKET_MQUEUE,
        SOCKET_USB_FUNCTION,
        _SOCKET_TYPE_MAX,
        _SOCKET_TYPE_INVALID = -EINVAL,
} SocketType;

typedef enum SocketResult {
        SOCKET_SUCCESS,
        SOCKET_FAILURE_RESOURCES,
        SOCKET_FAILURE_TIMEOUT,
        SOCKET_FAILURE_EXIT_CODE,
        SOCKET_FAILURE_SIGNAL,
        SOCKET_FAILURE_CORE_DUMP,
        SOCKET_FAILURE_START_LIMIT_HIT,
        SOCKET_FAILURE_TRIGGER_LIMIT_HIT,
        SOCKET_FAILURE_SERVICE_START_LIMIT_HIT,
        _SOCKET_RESULT_MAX,
        _SOCKET_RESULT_INVALID = -EINVAL,
} SocketResult;

typedef struct SocketPort {
        Socket *socket;

        SocketType type;
        int fd;
        int *auxiliary_fds;
        size_t n_auxiliary_fds;

        SocketAddress address;
        char *path;
        sd_event_source *event_source;

        LIST_FIELDS(struct SocketPort, port);
} SocketPort;

typedef enum SocketTimestamping {
        SOCKET_TIMESTAMPING_OFF,
        SOCKET_TIMESTAMPING_US,  /* SO_TIMESTAMP */
        SOCKET_TIMESTAMPING_NS,  /* SO_TIMESTAMPNS */
        _SOCKET_TIMESTAMPING_MAX,
        _SOCKET_TIMESTAMPING_INVALID = -EINVAL,
} SocketTimestamping;

struct Socket {
        Unit meta;

        LIST_HEAD(SocketPort, ports);

        Set *peers_by_address;

        unsigned n_accepted;
        unsigned n_connections;
        unsigned n_refused;
        unsigned max_connections;
        unsigned max_connections_per_source;

        unsigned backlog;
        unsigned keep_alive_cnt;
        usec_t timeout_usec;
        usec_t keep_alive_time;
        usec_t keep_alive_interval;
        usec_t defer_accept;

        ExecCommand* exec_command[_SOCKET_EXEC_COMMAND_MAX];
        ExecContext exec_context;
        KillContext kill_context;
        CGroupContext cgroup_context;

        ExecRuntime *exec_runtime;
        CGroupRuntime *cgroup_runtime;

        /* For Accept=no sockets refers to the one service we'll
         * activate. For Accept=yes sockets is either NULL, or filled
         * to refer to the next service we spawn. */
        UnitRef service;

        SocketState state, deserialized_state;

        sd_event_source *timer_event_source;

        ExecCommand* control_command;
        SocketExecCommand control_command_id;
        PidRef control_pid;

        mode_t directory_mode;
        mode_t socket_mode;

        SocketResult result;
        SocketResult clean_result;

        char **symlinks;

        bool accept;
        bool remove_on_stop;
        bool writable;
        bool flush_pending;

        int socket_protocol;

        /* Socket options */
        bool keep_alive;
        bool no_delay;
        bool free_bind;
        bool transparent;
        bool broadcast;
        bool pass_cred;
        bool pass_fds_to_exec;
        bool pass_sec;
        bool pass_pktinfo;
        SocketTimestamping timestamping;

        /* Only for INET6 sockets: issue IPV6_V6ONLY sockopt */
        SocketAddressBindIPv6Only bind_ipv6_only;

        int priority;
        int mark;
        size_t receive_buffer;
        size_t send_buffer;
        int ip_tos;
        int ip_ttl;
        size_t pipe_size;
        char *bind_to_device;
        char *tcp_congestion;
        bool reuse_port;
        long mq_maxmsg;
        long mq_msgsize;

        char *smack;
        char *smack_ip_in;
        char *smack_ip_out;

        bool selinux_context_from_net;

        char *user, *group;

        char *fdname;

        RateLimit trigger_limit;
        RateLimit poll_limit;
};

SocketPeer *socket_peer_ref(SocketPeer *p);
SocketPeer *socket_peer_unref(SocketPeer *p);
int socket_acquire_peer(Socket *s, int fd, SocketPeer **p);

DEFINE_TRIVIAL_CLEANUP_FUNC(SocketPeer*, socket_peer_unref);

/* Called from the service code when collecting fds */
int socket_collect_fds(Socket *s, int **ret);

/* Called from the service code when a per-connection service ended */
void socket_connection_unref(Socket *s);

SocketPort* socket_port_free(SocketPort *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(SocketPort*, socket_port_free);

void socket_free_ports(Socket *s);

int socket_port_to_address(const SocketPort *s, char **ret);

int socket_load_service_unit(Socket *s, int cfd, Unit **ret);

const char* socket_fdname(Socket *s);

extern const UnitVTable socket_vtable;

const char* socket_exec_command_to_string(SocketExecCommand i) _const_;
SocketExecCommand socket_exec_command_from_string(const char *s) _pure_;

const char* socket_result_to_string(SocketResult i) _const_;
SocketResult socket_result_from_string(const char *s) _pure_;

const char* socket_port_type_to_string(SocketPort *p) _pure_;
SocketType socket_port_type_from_string(const char *p) _pure_;

const char* socket_timestamping_to_string(SocketTimestamping p) _const_;
SocketTimestamping socket_timestamping_from_string(const char *p) _pure_;
SocketTimestamping socket_timestamping_from_string_harder(const char *p) _pure_;

DEFINE_CAST(SOCKET, Socket);
