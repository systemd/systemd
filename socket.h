/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosockethfoo
#define foosockethfoo

typedef struct Socket Socket;

#include "name.h"
#include "socket-util.h"

typedef enum SocketState {
        SOCKET_DEAD,
        SOCKET_START_PRE,
        SOCKET_START_POST,
        SOCKET_LISTENING,
        SOCKET_RUNNING,
        SOCKET_STOP_PRE,
        SOCKET_STOP_POST,
        SOCKET_MAINTAINANCE,
        _SOCKET_STATE_MAX
} SocketState;

typedef enum SocketExecCommand {
        SOCKET_EXEC_START_PRE,
        SOCKET_EXEC_START_POST,
        SOCKET_EXEC_STOP_PRE,
        SOCKET_EXEC_STOP_POST,
        _SOCKET_EXEC_MAX
} SocketExecCommand;

typedef enum SocketType {
        SOCKET_SOCKET,
        SOCKET_FIFO
} SocketType;

typedef struct SocketPort SocketPort;

struct SocketPort {
        SocketType type;

        SocketAddress address;
        char *path;

        int fd;

        LIST_FIELDS(SocketPort);
};

struct Socket {
        Meta meta;

        SocketState state;

        LIST_HEAD(SocketPort, ports);

        /* Only for INET6 sockets: issue IPV6_V6ONLY sockopt */
        bool bind_ipv6_only;
        unsigned backlog;

        ExecCommand* exec_command[_SOCKET_EXEC_MAX];
        ExecContext exec_context;

        pid_t control_pid;

        Service *service;
};

extern const NameVTable socket_vtable;

#endif
