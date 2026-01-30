/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

/* The enum order is used to order unit jobs in the job queue
 * when other criteria (cpu weight, nice level) are identical.
 * In this case service units have the highest priority. */
typedef enum UnitType {
        UNIT_SERVICE,
        UNIT_MOUNT,
        UNIT_SWAP,
        UNIT_SOCKET,
        UNIT_TARGET,
        UNIT_DEVICE,
        UNIT_AUTOMOUNT,
        UNIT_TIMER,
        UNIT_PATH,
        UNIT_SLICE,
        UNIT_SCOPE,
        _UNIT_TYPE_MAX,
        _UNIT_TYPE_INVALID = -EINVAL,
        _UNIT_TYPE_ERRNO_MAX = -ERRNO_MAX, /* Ensure the whole errno range fits into this enum */
} UnitType;

typedef enum UnitLoadState {
        UNIT_STUB,
        UNIT_LOADED,
        UNIT_NOT_FOUND,    /* error condition #1: unit file not found */
        UNIT_BAD_SETTING,  /* error condition #2: we couldn't parse some essential unit file setting */
        UNIT_ERROR,        /* error condition #3: other "system" error, catchall for the rest */
        UNIT_MERGED,
        UNIT_MASKED,
        _UNIT_LOAD_STATE_MAX,
        _UNIT_LOAD_STATE_INVALID = -EINVAL,
} UnitLoadState;

typedef enum UnitActiveState {
        UNIT_ACTIVE,
        UNIT_RELOADING,
        UNIT_INACTIVE,
        UNIT_FAILED,
        UNIT_ACTIVATING,
        UNIT_DEACTIVATING,
        UNIT_MAINTENANCE,
        UNIT_REFRESHING,
        _UNIT_ACTIVE_STATE_MAX,
        _UNIT_ACTIVE_STATE_INVALID = -EINVAL,
} UnitActiveState;

typedef enum FreezerState {
        FREEZER_RUNNING,
        FREEZER_FREEZING, /* freezing due to user request */
        FREEZER_FROZEN,
        FREEZER_FREEZING_BY_PARENT, /* freezing as a result of parent slice freezing */
        FREEZER_FROZEN_BY_PARENT,
        FREEZER_THAWING,
        _FREEZER_STATE_MAX,
        _FREEZER_STATE_INVALID = -EINVAL,
} FreezerState;

typedef enum UnitMarker {
        UNIT_MARKER_NEEDS_RELOAD,
        UNIT_MARKER_NEEDS_RESTART,
        _UNIT_MARKER_MAX,
        _UNIT_MARKER_INVALID = -EINVAL,
} UnitMarker;

typedef enum AutomountState {
        AUTOMOUNT_DEAD,
        AUTOMOUNT_WAITING,
        AUTOMOUNT_RUNNING,
        AUTOMOUNT_FAILED,
        _AUTOMOUNT_STATE_MAX,
        _AUTOMOUNT_STATE_INVALID = -EINVAL,
} AutomountState;

/* We simply watch devices, we cannot plug/unplug them. That
 * simplifies the state engine greatly */
typedef enum DeviceState {
        DEVICE_DEAD,
        DEVICE_TENTATIVE, /* mounted or swapped, but not (yet) announced by udev */
        DEVICE_PLUGGED,   /* announced by udev */
        _DEVICE_STATE_MAX,
        _DEVICE_STATE_INVALID = -EINVAL,
} DeviceState;

typedef enum MountState {
        MOUNT_DEAD,
        MOUNT_MOUNTING,               /* /usr/bin/mount is running, but the mount is not done yet. */
        MOUNT_MOUNTING_DONE,          /* /usr/bin/mount is running, and the mount is done. */
        MOUNT_MOUNTED,
        MOUNT_REMOUNTING,
        MOUNT_UNMOUNTING,
        MOUNT_REMOUNTING_SIGTERM,
        MOUNT_REMOUNTING_SIGKILL,
        MOUNT_UNMOUNTING_SIGTERM,
        MOUNT_UNMOUNTING_SIGKILL,
        MOUNT_FAILED,
        MOUNT_CLEANING,
        _MOUNT_STATE_MAX,
        _MOUNT_STATE_INVALID = -EINVAL,
} MountState;

typedef enum PathState {
        PATH_DEAD,
        PATH_WAITING,
        PATH_RUNNING,
        PATH_FAILED,
        _PATH_STATE_MAX,
        _PATH_STATE_INVALID = -EINVAL,
} PathState;

typedef enum ScopeState {
        SCOPE_DEAD,
        SCOPE_START_CHOWN,
        SCOPE_RUNNING,
        SCOPE_ABANDONED,
        SCOPE_STOP_SIGTERM,
        SCOPE_STOP_SIGKILL,
        SCOPE_FAILED,
        _SCOPE_STATE_MAX,
        _SCOPE_STATE_INVALID = -EINVAL,
} ScopeState;

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_CONDITION,
        SERVICE_START_PRE,
        SERVICE_START,
        SERVICE_START_POST,
        SERVICE_RUNNING,
        SERVICE_EXITED,                 /* Nothing is running anymore, but RemainAfterExit is true hence this is OK */
        SERVICE_REFRESH_EXTENSIONS,     /* Refreshing extensions for a reload request */
        SERVICE_REFRESH_CREDENTIALS,    /* ditto, but for credentials */
        SERVICE_RELOAD,                 /* Reloading via ExecReload= */
        SERVICE_RELOAD_SIGNAL,          /* Reloading via SIGHUP requested */
        SERVICE_RELOAD_NOTIFY,          /* Waiting for READY=1 after RELOADING=1 notify */
        SERVICE_RELOAD_POST,
        SERVICE_MOUNTING,               /* Performing a live mount into the namespace of the service */
        SERVICE_STOP,                   /* No STOP_PRE state, instead just register multiple STOP executables */
        SERVICE_STOP_WATCHDOG,
        SERVICE_STOP_SIGTERM,
        SERVICE_STOP_SIGKILL,
        SERVICE_STOP_POST,
        SERVICE_FINAL_WATCHDOG,         /* In case the STOP_POST executable needs to be aborted. */
        SERVICE_FINAL_SIGTERM,          /* In case the STOP_POST executable hangs, we shoot that down, too */
        SERVICE_FINAL_SIGKILL,
        SERVICE_FAILED,
        SERVICE_DEAD_BEFORE_AUTO_RESTART,
        SERVICE_FAILED_BEFORE_AUTO_RESTART,
        SERVICE_DEAD_RESOURCES_PINNED,  /* Like SERVICE_DEAD, but with pinned resources */
        SERVICE_AUTO_RESTART,
        SERVICE_AUTO_RESTART_QUEUED,
        SERVICE_CLEANING,
        _SERVICE_STATE_MAX,
        _SERVICE_STATE_INVALID = -EINVAL,
} ServiceState;

typedef enum SliceState {
        SLICE_DEAD,
        SLICE_ACTIVE,
        _SLICE_STATE_MAX,
        _SLICE_STATE_INVALID = -EINVAL,
} SliceState;

typedef enum SocketState {
        SOCKET_DEAD,
        SOCKET_START_PRE,
        SOCKET_START_OPEN,
        SOCKET_START_CHOWN,
        SOCKET_START_POST,
        SOCKET_LISTENING,
        SOCKET_DEFERRED,
        SOCKET_RUNNING,
        SOCKET_STOP_PRE,
        SOCKET_STOP_PRE_SIGTERM,
        SOCKET_STOP_PRE_SIGKILL,
        SOCKET_STOP_POST,
        SOCKET_FINAL_SIGTERM,
        SOCKET_FINAL_SIGKILL,
        SOCKET_FAILED,
        SOCKET_CLEANING,
        _SOCKET_STATE_MAX,
        _SOCKET_STATE_INVALID = -EINVAL,
} SocketState;

typedef enum SwapState {
        SWAP_DEAD,
        SWAP_ACTIVATING,               /* /sbin/swapon is running, but the swap not yet enabled. */
        SWAP_ACTIVATING_DONE,          /* /sbin/swapon is running, and the swap is done. */
        SWAP_ACTIVE,
        SWAP_DEACTIVATING,
        SWAP_DEACTIVATING_SIGTERM,
        SWAP_DEACTIVATING_SIGKILL,
        SWAP_FAILED,
        SWAP_CLEANING,
        _SWAP_STATE_MAX,
        _SWAP_STATE_INVALID = -EINVAL,
} SwapState;

typedef enum TargetState {
        TARGET_DEAD,
        TARGET_ACTIVE,
        _TARGET_STATE_MAX,
        _TARGET_STATE_INVALID = -EINVAL,
} TargetState;

typedef enum TimerState {
        TIMER_DEAD,
        TIMER_WAITING,
        TIMER_RUNNING,
        TIMER_ELAPSED,
        TIMER_FAILED,
        _TIMER_STATE_MAX,
        _TIMER_STATE_INVALID = -EINVAL,
} TimerState;

typedef enum UnitDependency {
        /* Positive dependencies */
        UNIT_REQUIRES,
        UNIT_REQUISITE,
        UNIT_WANTS,
        UNIT_BINDS_TO,
        UNIT_PART_OF,
        UNIT_UPHOLDS,

        /* Inverse of the above */
        UNIT_REQUIRED_BY,             /* inverse of 'requires' is 'required_by' */
        UNIT_REQUISITE_OF,            /* inverse of 'requisite' is 'requisite_of' */
        UNIT_WANTED_BY,               /* inverse of 'wants' */
        UNIT_BOUND_BY,                /* inverse of 'binds_to' */
        UNIT_CONSISTS_OF,             /* inverse of 'part_of' */
        UNIT_UPHELD_BY,               /* inverse of 'uphold' */

        /* Negative dependencies */
        UNIT_CONFLICTS,               /* inverse of 'conflicts' is 'conflicted_by' */
        UNIT_CONFLICTED_BY,

        /* Order */
        UNIT_BEFORE,                  /* inverse of 'before' is 'after' and vice versa */
        UNIT_AFTER,

        /* OnSuccess= + OnFailure= */
        UNIT_ON_SUCCESS,
        UNIT_ON_SUCCESS_OF,
        UNIT_ON_FAILURE,
        UNIT_ON_FAILURE_OF,

        /* Triggers (i.e. a socket triggers a service) */
        UNIT_TRIGGERS,
        UNIT_TRIGGERED_BY,

        /* Propagate reloads */
        UNIT_PROPAGATES_RELOAD_TO,
        UNIT_RELOAD_PROPAGATED_FROM,

        /* Propagate stops */
        UNIT_PROPAGATES_STOP_TO,
        UNIT_STOP_PROPAGATED_FROM,

        /* Joins namespace of */
        UNIT_JOINS_NAMESPACE_OF,

        /* Reference information for GC logic */
        UNIT_REFERENCES,              /* Inverse of 'references' is 'referenced_by' */
        UNIT_REFERENCED_BY,

        /* Slice= */
        UNIT_IN_SLICE,
        UNIT_SLICE_OF,

        _UNIT_DEPENDENCY_MAX,
        _UNIT_DEPENDENCY_INVALID = -EINVAL,
} UnitDependency;

typedef enum NotifyAccess {
        NOTIFY_NONE,
        NOTIFY_ALL,
        NOTIFY_MAIN,
        NOTIFY_EXEC,
        _NOTIFY_ACCESS_MAX,
        _NOTIFY_ACCESS_INVALID = -EINVAL,
} NotifyAccess;

typedef enum JobMode {
        JOB_FAIL,                 /* Fail if a conflicting job is already queued */
        JOB_LENIENT,              /* Fail if any conflicting unit is active (even weaker than JOB_FAIL) */
        JOB_REPLACE,              /* Replace an existing conflicting job */
        JOB_REPLACE_IRREVERSIBLY, /* Like JOB_REPLACE + produce irreversible jobs */
        JOB_ISOLATE,              /* Start a unit, and stop all others */
        JOB_FLUSH,                /* Flush out all other queued jobs when queueing this one */
        JOB_IGNORE_DEPENDENCIES,  /* Ignore both requirement and ordering dependencies */
        JOB_IGNORE_REQUIREMENTS,  /* Ignore requirement dependencies */
        JOB_TRIGGERING,           /* Adds TRIGGERED_BY dependencies to the same transaction */
        JOB_RESTART_DEPENDENCIES, /* A "start" job for the specified unit becomes "restart" for depending units */
        _JOB_MODE_MAX,
        _JOB_MODE_INVALID = -EINVAL,
} JobMode;

typedef enum ExecDirectoryType {
        EXEC_DIRECTORY_RUNTIME,
        EXEC_DIRECTORY_STATE,
        EXEC_DIRECTORY_CACHE,
        EXEC_DIRECTORY_LOGS,
        EXEC_DIRECTORY_CONFIGURATION,
        _EXEC_DIRECTORY_TYPE_MAX,
        _EXEC_DIRECTORY_TYPE_INVALID = -EINVAL,
} ExecDirectoryType;

char* unit_dbus_path_from_name(const char *name);
int unit_name_from_dbus_path(const char *path, char **name);

const char* unit_dbus_interface_from_type(UnitType t);
const char* unit_dbus_interface_from_name(const char *name);

DECLARE_STRING_TABLE_LOOKUP(unit_type, UnitType);
void unit_types_list(void);

DECLARE_STRING_TABLE_LOOKUP(unit_load_state, UnitLoadState);
DECLARE_STRING_TABLE_LOOKUP(unit_active_state, UnitActiveState);

DECLARE_STRING_TABLE_LOOKUP(freezer_state, FreezerState);
FreezerState freezer_state_finish(FreezerState state) _const_;
FreezerState freezer_state_objective(FreezerState state) _const_;

DECLARE_STRING_TABLE_LOOKUP(unit_marker, UnitMarker);
DECLARE_STRING_TABLE_LOOKUP(automount_state, AutomountState);
DECLARE_STRING_TABLE_LOOKUP(device_state, DeviceState);
DECLARE_STRING_TABLE_LOOKUP(mount_state, MountState);
DECLARE_STRING_TABLE_LOOKUP(path_state, PathState);
DECLARE_STRING_TABLE_LOOKUP(scope_state, ScopeState);
DECLARE_STRING_TABLE_LOOKUP(service_state, ServiceState);
DECLARE_STRING_TABLE_LOOKUP(slice_state, SliceState);
DECLARE_STRING_TABLE_LOOKUP(socket_state, SocketState);
DECLARE_STRING_TABLE_LOOKUP(swap_state, SwapState);
DECLARE_STRING_TABLE_LOOKUP(target_state, TargetState);
DECLARE_STRING_TABLE_LOOKUP(timer_state, TimerState);
DECLARE_STRING_TABLE_LOOKUP(unit_dependency, UnitDependency);
DECLARE_STRING_TABLE_LOOKUP(notify_access, NotifyAccess);
DECLARE_STRING_TABLE_LOOKUP(job_mode, JobMode);
DECLARE_STRING_TABLE_LOOKUP(exec_directory_type, ExecDirectoryType);

Glyph unit_active_state_to_glyph(UnitActiveState state);
