/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooservicehfoo
#define fooservicehfoo

typedef struct Service Service;

#include "unit.h"
#include "ratelimit.h"

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_START_PRE,
        SERVICE_START,
        SERVICE_START_POST,
        SERVICE_RUNNING,
        SERVICE_RELOAD,
        SERVICE_STOP,              /* No STOP_PRE state, instead just register multiple STOP executables */
        SERVICE_STOP_SIGTERM,
        SERVICE_STOP_SIGKILL,
        SERVICE_STOP_POST,
        SERVICE_FINAL_SIGTERM,     /* In case the STOP_POST executable hangs, we shoot that down, too */
        SERVICE_FINAL_SIGKILL,
        SERVICE_MAINTAINANCE,
        SERVICE_AUTO_RESTART,
        _SERVICE_STATE_MAX,
} ServiceState;

typedef enum ServiceRestart {
        SERVICE_ONCE,
        SERVICE_RESTART_ON_SUCCESS,
        SERVICE_RESTART_ALWAYS
} ServiceRestart;

typedef enum ServiceType {
        SERVICE_FORKING,
        SERVICE_SIMPLE
} ServiceType;

typedef enum ServiceExecCommand {
        SERVICE_EXEC_START_PRE,
        SERVICE_EXEC_START,
        SERVICE_EXEC_START_POST,
        SERVICE_EXEC_RELOAD,
        SERVICE_EXEC_STOP,
        SERVICE_EXEC_STOP_POST,
        _SERVICE_EXEC_MAX
} ServiceExecCommand;

struct Service {
        Meta meta;

        ServiceType type;
        ServiceRestart restart;

        /* If set we'll read the main daemon PID from this file */
        char *pid_file;

        usec_t restart_usec;
        usec_t timeout_usec;

        ExecCommand* exec_command[_SERVICE_EXEC_MAX];
        ExecContext exec_context;

        ServiceState state;

        ExecStatus main_exec_status;

        ExecCommand *control_command;
        pid_t main_pid, control_pid;
        bool main_pid_known:1;

        bool failure:1; /* if we shut down, remember why */
        Watch timer_watch;

        RateLimit ratelimit;
};

const UnitVTable service_vtable;

#endif
