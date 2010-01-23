/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooservicehfoo
#define fooservicehfoo

typedef struct Service Service;

#include "name.h"
#include "socket.h"
#include "timer.h"

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_START_PRE,
        SERVICE_START,
        SERVICE_START_POST,
        SERVICE_RUNNING,
        SERVICE_RELOAD_PRE,
        SERVICE_RELOAD,
        SERVICE_RELOAD_POST,
        SERVICE_STOP_PRE,
        SERVICE_STOP,
        SERVICE_SIGTERM,
        SERVICE_SIGKILL,
        SERVICE_STOP_POST,
        SERVICE_MAINTAINANCE,
        _SERVICE_STATE_MAX,
} ServiceState;

typedef enum ServiceMode {
        SERVICE_ONCE,
        SERVICE_RESTART
} ServiceMode;

typedef enum ServiceExecCommand {
        SERVICE_EXEC_START_PRE,
        SERVICE_EXEC_START,
        SERVICE_EXEC_START_POST,
        SERVICE_EXEC_RELOAD_PRE,
        SERVICE_EXEC_RELOAD,
        SERVICE_EXEC_RELOAD_POST,
        SERVICE_EXEC_STOP_PRE,
        SERVICE_EXEC_STOP,
        SERVICE_EXEC_STOP_POST,
        _SERVICE_EXEC_MAX
} ServiceExecCommand;

struct Service {
        Meta meta;

        ServiceState state;
        ServiceMode mode;

        ExecCommand* exec_command[_SERVICE_EXEC_MAX];
        ExecContext exec_context;

        pid_t service_pid, control_pid;

        Socket *socket;
        Timer *timer;
};

const NameVTable service_vtable;

#endif
