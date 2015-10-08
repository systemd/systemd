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

typedef struct Service Service;
typedef struct ServiceFDStore ServiceFDStore;

#include "path.h"
#include "ratelimit.h"
#include "kill.h"
#include "exit-status.h"

typedef enum ServiceRestart {
        SERVICE_RESTART_NO,
        SERVICE_RESTART_ON_SUCCESS,
        SERVICE_RESTART_ON_FAILURE,
        SERVICE_RESTART_ON_ABNORMAL,
        SERVICE_RESTART_ON_WATCHDOG,
        SERVICE_RESTART_ON_ABORT,
        SERVICE_RESTART_ALWAYS,
        _SERVICE_RESTART_MAX,
        _SERVICE_RESTART_INVALID = -1
} ServiceRestart;

typedef enum ServiceType {
        SERVICE_SIMPLE,   /* we fork and go on right-away (i.e. modern socket activated daemons) */
        SERVICE_FORKING,  /* forks by itself (i.e. traditional daemons) */
        SERVICE_ONESHOT,  /* we fork and wait until the program finishes (i.e. programs like fsck which run and need to finish before we continue) */
        SERVICE_DBUS,     /* we fork and wait until a specific D-Bus name appears on the bus */
        SERVICE_NOTIFY,   /* we fork and wait until a daemon sends us a ready message with sd_notify() */
        SERVICE_IDLE,     /* much like simple, but delay exec() until all jobs are dispatched. */
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
        _SERVICE_EXEC_COMMAND_MAX,
        _SERVICE_EXEC_COMMAND_INVALID = -1
} ServiceExecCommand;

typedef enum NotifyAccess {
        NOTIFY_NONE,
        NOTIFY_ALL,
        NOTIFY_MAIN,
        _NOTIFY_ACCESS_MAX,
        _NOTIFY_ACCESS_INVALID = -1
} NotifyAccess;

typedef enum NotifyState {
        NOTIFY_UNKNOWN,
        NOTIFY_READY,
        NOTIFY_RELOADING,
        NOTIFY_STOPPING,
        _NOTIFY_STATE_MAX,
        _NOTIFY_STATE_INVALID = -1
} NotifyState;

typedef enum ServiceResult {
        SERVICE_SUCCESS,
        SERVICE_FAILURE_RESOURCES,
        SERVICE_FAILURE_TIMEOUT,
        SERVICE_FAILURE_EXIT_CODE,
        SERVICE_FAILURE_SIGNAL,
        SERVICE_FAILURE_CORE_DUMP,
        SERVICE_FAILURE_WATCHDOG,
        SERVICE_FAILURE_START_LIMIT,
        _SERVICE_RESULT_MAX,
        _SERVICE_RESULT_INVALID = -1
} ServiceResult;

struct ServiceFDStore {
        Service *service;

        int fd;
        char *fdname;
        sd_event_source *event_source;

        LIST_FIELDS(ServiceFDStore, fd_store);
};

struct Service {
        Unit meta;

        ServiceType type;
        ServiceRestart restart;
        ExitStatusSet restart_prevent_status;
        ExitStatusSet restart_force_status;
        ExitStatusSet success_status;

        /* If set we'll read the main daemon PID from this file */
        char *pid_file;

        usec_t restart_usec;
        usec_t timeout_start_usec;
        usec_t timeout_stop_usec;

        dual_timestamp watchdog_timestamp;
        usec_t watchdog_usec;
        sd_event_source *watchdog_event_source;

        ExecCommand* exec_command[_SERVICE_EXEC_COMMAND_MAX];

        ExecContext exec_context;
        KillContext kill_context;
        CGroupContext cgroup_context;

        ServiceState state, deserialized_state;

        /* The exit status of the real main process */
        ExecStatus main_exec_status;

        /* The currently executed control process */
        ExecCommand *control_command;

        /* The currently executed main process, which may be NULL if
         * the main process got started via forking mode and not by
         * us */
        ExecCommand *main_command;

        /* The ID of the control command currently being executed */
        ServiceExecCommand control_command_id;

        /* Runtime data of the execution context */
        ExecRuntime *exec_runtime;

        pid_t main_pid, control_pid;
        int socket_fd;
        bool socket_fd_selinux_context_net;

        int bus_endpoint_fd;

        bool permissions_start_only;
        bool root_directory_start_only;
        bool remain_after_exit;
        bool guess_main_pid;

        /* If we shut down, remember why */
        ServiceResult result;
        ServiceResult reload_result;

        bool main_pid_known:1;
        bool main_pid_alien:1;
        bool bus_name_good:1;
        bool forbid_restart:1;
        bool start_timeout_defined:1;

        bool reset_cpu_usage:1;

        char *bus_name;

        char *status_text;
        int status_errno;

        RateLimit start_limit;
        FailureAction start_limit_action;
        FailureAction failure_action;
        char *reboot_arg;

        UnitRef accept_socket;

        sd_event_source *timer_event_source;
        PathSpec *pid_file_pathspec;

        NotifyAccess notify_access;
        NotifyState notify_state;

        ServiceFDStore *fd_store;
        unsigned n_fd_store;
        unsigned n_fd_store_max;

        char *usb_function_descriptors;
        char *usb_function_strings;

        int stdin_fd;
        int stdout_fd;
        int stderr_fd;
};

extern const UnitVTable service_vtable;

int service_set_socket_fd(Service *s, int fd, struct Socket *socket, bool selinux_context_net);

const char* service_restart_to_string(ServiceRestart i) _const_;
ServiceRestart service_restart_from_string(const char *s) _pure_;

const char* service_type_to_string(ServiceType i) _const_;
ServiceType service_type_from_string(const char *s) _pure_;

const char* service_exec_command_to_string(ServiceExecCommand i) _const_;
ServiceExecCommand service_exec_command_from_string(const char *s) _pure_;

const char* notify_access_to_string(NotifyAccess i) _const_;
NotifyAccess notify_access_from_string(const char *s) _pure_;

const char* notify_state_to_string(NotifyState i) _const_;
NotifyState notify_state_from_string(const char *s) _pure_;

const char* service_result_to_string(ServiceResult i) _const_;
ServiceResult service_result_from_string(const char *s) _pure_;
