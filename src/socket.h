/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosockethfoo
#define foosockethfoo

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

typedef struct Socket Socket;

#include "manager.h"
#include "unit.h"
#include "socket-util.h"
#include "mount.h"

typedef enum SocketState {
        SOCKET_DEAD,
        SOCKET_START_PRE,
        SOCKET_START_POST,
        SOCKET_LISTENING,
        SOCKET_RUNNING,
        SOCKET_STOP_PRE,
        SOCKET_STOP_PRE_SIGTERM,
        SOCKET_STOP_PRE_SIGKILL,
        SOCKET_STOP_POST,
        SOCKET_FINAL_SIGTERM,
        SOCKET_FINAL_SIGKILL,
        SOCKET_MAINTENANCE,
        _SOCKET_STATE_MAX,
        _SOCKET_STATE_INVALID = -1
} SocketState;

typedef enum SocketExecCommand {
        SOCKET_EXEC_START_PRE,
        SOCKET_EXEC_START_POST,
        SOCKET_EXEC_STOP_PRE,
        SOCKET_EXEC_STOP_POST,
        _SOCKET_EXEC_COMMAND_MAX,
        _SOCKET_EXEC_COMMAND_INVALID = -1
} SocketExecCommand;

typedef enum SocketType {
        SOCKET_SOCKET,
        SOCKET_FIFO,
        _SOCKET_FIFO_MAX,
        _SOCKET_FIFO_INVALID = -1
} SocketType;

typedef struct SocketPort {
        SocketType type;
        int fd;

        SocketAddress address;
        char *path;
        Watch fd_watch;

        LIST_FIELDS(struct SocketPort, port);
} SocketPort;

struct Socket {
        Meta meta;

        LIST_HEAD(SocketPort, ports);

        unsigned backlog;
        usec_t timeout_usec;

        ExecCommand* exec_command[_SOCKET_EXEC_COMMAND_MAX];
        ExecContext exec_context;

        Service *service;

        SocketState state, deserialized_state;

        ExecCommand* control_command;
        SocketExecCommand control_command_id;
        pid_t control_pid;

        bool accept;
        unsigned n_accepted;
        unsigned n_connections;
        unsigned max_connections;

        bool failure;
        Watch timer_watch;

        /* Socket options */
        bool keep_alive;
        int priority;
        size_t receive_buffer;
        size_t send_buffer;
        int ip_tos;
        int ip_ttl;
        size_t pipe_size;
        int mark;
        bool free_bind;
        char *bind_to_device;

        /* Only for INET6 sockets: issue IPV6_V6ONLY sockopt */
        SocketAddressBindIPv6Only bind_ipv6_only;

        mode_t directory_mode;
        mode_t socket_mode;
};

/* Called from the service code when collecting fds */
int socket_collect_fds(Socket *s, int **fds, unsigned *n_fds);

/* Called from the service when it shut down */
void socket_notify_service_dead(Socket *s);

/* Called from the mount code figure out if a mount is a dependency of
 * any of the sockets of this socket */
int socket_add_one_mount_link(Socket *s, Mount *m);

/* Called from the service code when a per-connection service ended */
void socket_connection_unref(Socket *s);

extern const UnitVTable socket_vtable;

const char* socket_state_to_string(SocketState i);
SocketState socket_state_from_string(const char *s);

const char* socket_exec_command_to_string(SocketExecCommand i);
SocketExecCommand socket_exec_command_from_string(const char *s);

#endif
