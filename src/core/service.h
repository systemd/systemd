/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cgroup.h"
#include "core-forward.h"
#include "exit-status.h"
#include "kill.h"
#include "pidref.h"
#include "unit.h"

typedef enum ServiceRestart {
        SERVICE_RESTART_NO,
        SERVICE_RESTART_ON_SUCCESS,
        SERVICE_RESTART_ON_FAILURE,
        SERVICE_RESTART_ON_ABNORMAL,
        SERVICE_RESTART_ON_WATCHDOG,
        SERVICE_RESTART_ON_ABORT,
        SERVICE_RESTART_ALWAYS,
        _SERVICE_RESTART_MAX,
        _SERVICE_RESTART_INVALID = -EINVAL,
} ServiceRestart;

typedef enum ServiceType {
        SERVICE_SIMPLE,        /* we fork and go on right-away (i.e. modern socket activated daemons) */
        SERVICE_FORKING,       /* forks by itself (i.e. traditional daemons) */
        SERVICE_ONESHOT,       /* we fork and wait until the program finishes (i.e. programs like fsck which run and need to finish before we continue) */
        SERVICE_DBUS,          /* we fork and wait until a specific D-Bus name appears on the bus */
        SERVICE_NOTIFY,        /* we fork and wait until a daemon sends us a ready message with sd_notify() */
        SERVICE_NOTIFY_RELOAD, /* just like SERVICE_NOTIFY, but also implements a reload protocol via SIGHUP */
        SERVICE_IDLE,          /* much like simple, but delay exec() until all jobs are dispatched. */
        SERVICE_EXEC,          /* we fork and wait until we execute exec() (this means our own setup is waited for) */
        _SERVICE_TYPE_MAX,
        _SERVICE_TYPE_INVALID = -EINVAL,
} ServiceType;

typedef enum ServiceExitType {
        SERVICE_EXIT_MAIN,    /* we consider the main PID when deciding if the service exited */
        SERVICE_EXIT_CGROUP,  /* we wait for the last process in the cgroup to exit */
        _SERVICE_EXIT_TYPE_MAX,
        _SERVICE_EXIT_TYPE_INVALID = -EINVAL,
} ServiceExitType;

typedef enum ServiceExecCommand {
        SERVICE_EXEC_CONDITION,
        SERVICE_EXEC_START_PRE,
        SERVICE_EXEC_START,
        SERVICE_EXEC_START_POST,
        SERVICE_EXEC_RELOAD,
        SERVICE_EXEC_RELOAD_POST,
        SERVICE_EXEC_STOP,
        SERVICE_EXEC_STOP_POST,
        _SERVICE_EXEC_COMMAND_MAX,
        _SERVICE_EXEC_COMMAND_INVALID = -EINVAL,
} ServiceExecCommand;

typedef enum NotifyState {
        NOTIFY_READY,
        NOTIFY_RELOADING,
        NOTIFY_RELOAD_READY,
        NOTIFY_STOPPING,
        _NOTIFY_STATE_MAX,
        _NOTIFY_STATE_INVALID = -EINVAL,
} NotifyState;

/* The values of this enum are referenced in man/systemd.exec.xml and src/shared/bus-unit-util.c.
 * Update those sources for each change to this enum. */
typedef enum ServiceResult {
        SERVICE_SUCCESS,
        SERVICE_FAILURE_RESOURCES, /* a bit of a misnomer, just our catch-all error for errnos we didn't expect */
        SERVICE_FAILURE_PROTOCOL,
        SERVICE_FAILURE_TIMEOUT,
        SERVICE_FAILURE_EXIT_CODE,
        SERVICE_FAILURE_SIGNAL,
        SERVICE_FAILURE_CORE_DUMP,
        SERVICE_FAILURE_WATCHDOG,
        SERVICE_FAILURE_START_LIMIT_HIT,
        SERVICE_FAILURE_OOM_KILL, /* OOM Kill by the Kernel or systemd-oomd */
        SERVICE_SKIP_CONDITION,
        _SERVICE_RESULT_MAX,
        _SERVICE_RESULT_INVALID = -EINVAL,
} ServiceResult;

typedef enum ServiceTimeoutFailureMode {
        SERVICE_TIMEOUT_TERMINATE,
        SERVICE_TIMEOUT_ABORT,
        SERVICE_TIMEOUT_KILL,
        _SERVICE_TIMEOUT_FAILURE_MODE_MAX,
        _SERVICE_TIMEOUT_FAILURE_MODE_INVALID = -EINVAL,
} ServiceTimeoutFailureMode;

typedef enum ServiceRestartMode {
        SERVICE_RESTART_MODE_NORMAL,
        SERVICE_RESTART_MODE_DIRECT,
        SERVICE_RESTART_MODE_DEBUG,
        _SERVICE_RESTART_MODE_MAX,
        _SERVICE_RESTART_MODE_INVALID = -EINVAL,
} ServiceRestartMode;

typedef enum ServiceRefreshOnReload {
        SERVICE_RELOAD_EXTENSIONS  = 1 << 0,
        _SERVICE_REFRESH_ON_RELOAD_ALL = (1 << 1) - 1,
        _SERVICE_REFRESH_ON_RELOAD_INVALID = -EINVAL,
} ServiceRefreshOnReload;

#define SERVICE_REFRESH_ON_RELOAD_DEFAULT SERVICE_RELOAD_EXTENSIONS

typedef struct ServiceFDStore {
        Service *service;

        int fd;
        char *fdname;
        sd_event_source *event_source;
        bool do_poll;

        LIST_FIELDS(struct ServiceFDStore, fd_store);
} ServiceFDStore;

typedef struct ServiceExtraFD {
        int fd;
        char *fdname;
} ServiceExtraFD;

typedef struct Service {
        Unit meta;

        ServiceType type;
        ServiceExitType exit_type;
        ServiceRestart restart;
        ServiceRestartMode restart_mode;
        ExitStatusSet restart_prevent_status;
        ExitStatusSet restart_force_status;
        ExitStatusSet success_status;

        /* If set we'll read the main daemon PID from this file */
        char *pid_file;

        unsigned n_restarts;
        unsigned restart_steps;
        usec_t restart_usec;
        usec_t restart_max_delay_usec;
        usec_t timeout_start_usec;
        usec_t timeout_stop_usec;
        usec_t timeout_abort_usec;
        bool timeout_abort_set;
        usec_t runtime_max_usec;
        usec_t runtime_rand_extra_usec;
        ServiceTimeoutFailureMode timeout_start_failure_mode;
        ServiceTimeoutFailureMode timeout_stop_failure_mode;

        dual_timestamp watchdog_timestamp;
        usec_t watchdog_usec;            /* the requested watchdog timeout in the unit file */
        usec_t watchdog_original_usec;   /* the watchdog timeout that was in effect when the unit was started, i.e. the timeout the forked off processes currently see */
        usec_t watchdog_override_usec;   /* the watchdog timeout requested by the service itself through sd_notify() */
        bool watchdog_override_enable;
        sd_event_source *watchdog_event_source;

        ExecContext exec_context;
        KillContext kill_context;
        CGroupContext cgroup_context;

        ServiceState state, deserialized_state;

        /* The exit status of the real main process */
        ExecStatus main_exec_status;

        ExecCommand *exec_command[_SERVICE_EXEC_COMMAND_MAX];

        /* The currently executed main process, which may be NULL if the main process got started via
         * forking mode and not by us */
        ExecCommand *main_command;

        /* The currently executed control process */
        ExecCommand *control_command;

        /* The ID of the control command currently being executed */
        ServiceExecCommand control_command_id;

        /* Runtime data of the execution context */
        ExecRuntime *exec_runtime;

        CGroupRuntime *cgroup_runtime;

        PidRef main_pid, control_pid;

        /* if we are a socket activated service instance, store information of the connection/peer/socket */
        int socket_fd;
        SocketPeer *socket_peer;
        UnitRef accept_socket;
        bool socket_fd_selinux_context_net;

        bool permissions_start_only;
        bool root_directory_start_only;
        bool remain_after_exit;
        bool guess_main_pid;

        /* If we shut down, remember why */
        ServiceResult result;
        ServiceResult reload_result;
        ServiceResult live_mount_result;
        ServiceResult clean_result;

        bool main_pid_known:1;
        bool main_pid_alien:1;
        bool bus_name_good:1;
        bool forbid_restart:1;
        bool start_timeout_defined:1;
        bool exec_fd_hot:1;

        char *bus_name;

        char *status_text;
        char *status_bus_error;
        char *status_varlink_error;
        int status_errno;

        sd_event_source *timer_event_source;
        PathSpec *pid_file_pathspec;

        NotifyAccess notify_access;
        NotifyAccess notify_access_override;
        NotifyState notify_state;

        sd_bus_slot *bus_name_pid_lookup_slot;

        sd_event_source *exec_fd_event_source;

        LIST_HEAD(ServiceFDStore, fd_store);
        size_t n_fd_store;
        unsigned n_fd_store_max;
        ExecPreserveMode fd_store_preserve_mode;

        int stdin_fd;
        int stdout_fd;
        int stderr_fd;

        /* File descriptor received from RootDirectoryFileDescriptor= */
        int root_directory_fd;

        /* If service spawned from transient unit, extra file descriptors can be passed via dbus API */
        ServiceExtraFD *extra_fds;
        size_t n_extra_fds;

        LIST_HEAD(OpenFile, open_files);

        int reload_signal;
        usec_t reload_begin_usec;

        bool refresh_on_reload_set;
        ServiceRefreshOnReload refresh_on_reload_flags;

        OOMPolicy oom_policy;

        char *usb_function_descriptors;
        char *usb_function_strings;

        /* The D-Bus request, we will reply once the operation is finished, so that callers can block */
        sd_bus_message *mount_request;
} Service;

static inline usec_t service_timeout_abort_usec(Service *s) {
        assert(s);
        return s->timeout_abort_set ? s->timeout_abort_usec : s->timeout_stop_usec;
}

static inline NotifyAccess service_get_notify_access(Service *s) {
        assert(s);
        return s->notify_access_override < 0 ? s->notify_access : s->notify_access_override;
}

static inline usec_t service_get_watchdog_usec(Service *s) {
        assert(s);
        return s->watchdog_override_enable ? s->watchdog_override_usec : s->watchdog_original_usec;
}

extern const UnitVTable service_vtable;

int service_set_socket_fd(Service *s, int fd, struct Socket *socket, struct SocketPeer *peer, bool selinux_context_net);
void service_release_socket_fd(Service *s);

usec_t service_restart_usec_next(const Service *s) _pure_;

int service_determine_exec_selinux_label(Service *s, char **ret);

DECLARE_STRING_TABLE_LOOKUP(service_restart, ServiceRestart);

DECLARE_STRING_TABLE_LOOKUP(service_restart_mode, ServiceRestartMode);

DECLARE_STRING_TABLE_LOOKUP(service_type, ServiceType);

DECLARE_STRING_TABLE_LOOKUP(service_exit_type, ServiceExitType);

DECLARE_STRING_TABLE_LOOKUP(service_exec_command, ServiceExecCommand);

DECLARE_STRING_TABLE_LOOKUP(service_exec_ex_command, ServiceExecCommand);

DECLARE_STRING_TABLE_LOOKUP(notify_state, NotifyState);

DECLARE_STRING_TABLE_LOOKUP(service_result, ServiceResult);

DECLARE_STRING_TABLE_LOOKUP(service_timeout_failure_mode, ServiceTimeoutFailureMode);

ServiceRefreshOnReload service_refresh_on_reload_flag_from_string(const char *s) _pure_;
int service_refresh_on_reload_from_string_many(const char *s, ServiceRefreshOnReload *ret);
int service_refresh_on_reload_to_strv(ServiceRefreshOnReload flags, char ***ret);

DEFINE_CAST(SERVICE, Service);

/* Only exported for unit tests */
int service_deserialize_exec_command(Unit *u, const char *key, const char *value);
