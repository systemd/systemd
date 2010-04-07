/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooservicehfoo
#define fooservicehfoo

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
        _SERVICE_STATE_INVALID = -1
} ServiceState;

typedef enum ServiceRestart {
        SERVICE_ONCE,
        SERVICE_RESTART_ON_SUCCESS,
        SERVICE_RESTART_ALWAYS,
        _SERVICE_RESTART_MAX,
        _SERVICE_RESTART_INVALID = -1
} ServiceRestart;

typedef enum ServiceType {
        SERVICE_FORKING,  /* forks by itself (i.e. traditional daemons) */
        SERVICE_SIMPLE,   /* we fork and go on right-away (i.e. modern socket activated daemons)*/
        SERVICE_FINISH,   /* we fork and wait until the program finishes (i.e. programs like fsck which run and need to finish before we continue) */
        _SERVICE_TYPE_MAX,
        _SERVICE_TYPE_INVALID = -1
} ServiceType;

typedef enum ServiceExecCommand {
        SERVICE_EXEC_START_PRE,
        SERVICE_EXEC_START,
        SERVICE_EXEC_START_POST,
        SERVICE_EXEC_RELOAD,
        SERVICE_EXEC_STOP,
        SERVICE_EXEC_STOP_POST,
        _SERVICE_EXEC_MAX,
        _SERVICE_EXEC_INVALID = -1
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

        bool permissions_start_only;
        bool root_directory_start_only;
        bool valid_no_process;

        ServiceState state;

        ExecStatus main_exec_status;

        ExecCommand *control_command;
        pid_t main_pid, control_pid;
        bool main_pid_known:1;

        bool sysv_has_lsb:1;

        bool failure:1; /* if we shut down, remember why */
        Watch timer_watch;

        char *sysv_path;
        int sysv_start_priority;
        char *sysv_runlevels;

        RateLimit ratelimit;
};

extern const UnitVTable service_vtable;

const char* service_state_to_string(ServiceState i);
ServiceState service_state_from_string(const char *s);

const char* service_restart_to_string(ServiceRestart i);
ServiceRestart service_restart_from_string(const char *s);

const char* service_type_to_string(ServiceType i);
ServiceType service_type_from_string(const char *s);

const char* service_exec_command_to_string(ServiceExecCommand i);
ServiceExecCommand service_exec_command_from_string(const char *s);

#endif
