/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

typedef struct Socket Socket;

#include "socket-util.h"
#include "mount.h"
#include "service.h"

typedef enum SocketState {
        SOCKET_DEAD,
        SOCKET_START_PRE,
        SOCKET_START_CHOWN,
        SOCKET_START_POST,
        SOCKET_LISTENING,
        SOCKET_RUNNING,
        SOCKET_STOP_PRE,
        SOCKET_STOP_PRE_SIGTERM,
        SOCKET_STOP_PRE_SIGKILL,
        SOCKET_STOP_POST,
        SOCKET_FINAL_SIGTERM,
        SOCKET_FINAL_SIGKILL,
        SOCKET_FAILED,
        _SOCKET_STATE_MAX,
        _SOCKET_STATE_INVALID = -1
} SocketState;

typedef enum SocketExecCommand {
        SOCKET_EXEC_START_PRE,
        SOCKET_EXEC_START_CHOWN,
        SOCKET_EXEC_START_POST,
        SOCKET_EXEC_STOP_PRE,
        SOCKET_EXEC_STOP_POST,
        _SOCKET_EXEC_COMMAND_MAX,
        _SOCKET_EXEC_COMMAND_INVALID = -1
} SocketExecCommand;

typedef enum SocketType {
        SOCKET_SOCKET,
        SOCKET_FIFO,
        SOCKET_SPECIAL,
        SOCKET_MQUEUE,
        _SOCKET_FIFO_MAX,
        _SOCKET_FIFO_INVALID = -1
} SocketType;

typedef enum SocketResult {
        SOCKET_SUCCESS,
        SOCKET_FAILURE_RESOURCES,
        SOCKET_FAILURE_TIMEOUT,
        SOCKET_FAILURE_EXIT_CODE,
        SOCKET_FAILURE_SIGNAL,
        SOCKET_FAILURE_CORE_DUMP,
        SOCKET_FAILURE_SERVICE_FAILED_PERMANENT,
        _SOCKET_RESULT_MAX,
        _SOCKET_RESULT_INVALID = -1
} SocketResult;

typedef struct SocketPort {
        Socket *socket;

        SocketType type;
        int fd;

        SocketAddress address;
        char *path;
        sd_event_source *event_source;

        LIST_FIELDS(struct SocketPort, port);
} SocketPort;

struct Socket {
        Unit meta;

        LIST_HEAD(SocketPort, ports);

        unsigned n_accepted;
        unsigned n_connections;
        unsigned max_connections;

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

        /* For Accept=no sockets refers to the one service we'll
        activate. For Accept=yes sockets is either NULL, or filled
        when the next service we spawn. */
        UnitRef service;

        SocketState state, deserialized_state;

        sd_event_source *timer_event_source;

        ExecCommand* control_command;
        SocketExecCommand control_command_id;
        pid_t control_pid;

        mode_t directory_mode;
        mode_t socket_mode;

        SocketResult result;

        char **symlinks;

        bool accept;
        bool remove_on_stop;

        /* Socket options */
        bool keep_alive;
        bool no_delay;
        bool free_bind;
        bool transparent;
        bool broadcast;
        bool pass_cred;
        bool pass_sec;

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

        bool reset_cpu_usage:1;
};

/* Called from the service code when collecting fds */
int socket_collect_fds(Socket *s, int **fds, unsigned *n_fds);

/* Called from the service code when a per-connection service ended */
void socket_connection_unref(Socket *s);

void socket_free_ports(Socket *s);

extern const UnitVTable socket_vtable;

const char* socket_state_to_string(SocketState i) _const_;
SocketState socket_state_from_string(const char *s) _pure_;

const char* socket_exec_command_to_string(SocketExecCommand i) _const_;
SocketExecCommand socket_exec_command_from_string(const char *s) _pure_;

const char* socket_result_to_string(SocketResult i) _const_;
SocketResult socket_result_from_string(const char *s) _pure_;

const char* socket_port_type_to_string(SocketPort *p) _pure_;

int socket_instantiate_service(Socket *s);
