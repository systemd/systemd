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
        SOCKET_STOP_POST_SIGTERM,
        SOCKET_STOP_POST_SIGKILL,
        SOCKET_MAINTAINANCE,
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

typedef struct SocketPort SocketPort;

struct SocketPort {
        SocketType type;

        SocketAddress address;
        char *path;

        int fd;
        Watch fd_watch;

        LIST_FIELDS(SocketPort, port);
};

struct Socket {
        Meta meta;

        LIST_HEAD(SocketPort, ports);

        /* Only for INET6 sockets: issue IPV6_V6ONLY sockopt */
        bool bind_ipv6_only;
        unsigned backlog;

        usec_t timeout_usec;

        ExecCommand* exec_command[_SOCKET_EXEC_COMMAND_MAX];
        ExecContext exec_context;

        Service *service;

        SocketState state;

        KillMode kill_mode;

        ExecCommand* control_command;
        pid_t control_pid;

        char *bind_to_device;
        mode_t directory_mode;
        mode_t socket_mode;

        bool failure;
        Watch timer_watch;
};

/* Called from the service code when collecting fds */
int socket_collect_fds(Socket *s, int **fds, unsigned *n_fds);

/* Called from the service when it shut down */
void socket_notify_service_dead(Socket *s);

extern const UnitVTable socket_vtable;

#endif
