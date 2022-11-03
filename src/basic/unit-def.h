/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "errno-list.h"
#include "glyph-util.h"
#include "macro.h"

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
        _UNIT_ACTIVE_STATE_MAX,
        _UNIT_ACTIVE_STATE_INVALID = -EINVAL,
} UnitActiveState;

typedef enum FreezerState {
        FREEZER_RUNNING,
        FREEZER_FREEZING,
        FREEZER_FROZEN,
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
        SERVICE_EXITED,            /* Nothing is running anymore, but RemainAfterExit is true hence this is OK */
        SERVICE_RELOAD,
        SERVICE_STOP,              /* No STOP_PRE state, instead just register multiple STOP executables */
        SERVICE_STOP_WATCHDOG,
        SERVICE_STOP_SIGTERM,
        SERVICE_STOP_SIGKILL,
        SERVICE_STOP_POST,
        SERVICE_FINAL_WATCHDOG,    /* In case the STOP_POST executable needs to be aborted. */
        SERVICE_FINAL_SIGTERM,     /* In case the STOP_POST executable hangs, we shoot that down, too */
        SERVICE_FINAL_SIGKILL,
        SERVICE_FAILED,
        SERVICE_AUTO_RESTART,
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

char *unit_dbus_path_from_name(const char *name);
int unit_name_from_dbus_path(const char *path, char **name);

const char* unit_dbus_interface_from_type(UnitType t);
const char *unit_dbus_interface_from_name(const char *name);

const char *unit_type_to_string(UnitType i) _const_;
UnitType unit_type_from_string(const char *s) _pure_;

const char *unit_load_state_to_string(UnitLoadState i) _const_;
UnitLoadState unit_load_state_from_string(const char *s) _pure_;

const char *unit_active_state_to_string(UnitActiveState i) _const_;
UnitActiveState unit_active_state_from_string(const char *s) _pure_;

const char *freezer_state_to_string(FreezerState i) _const_;
FreezerState freezer_state_from_string(const char *s) _pure_;

const char *unit_marker_to_string(UnitMarker m) _const_;
UnitMarker unit_marker_from_string(const char *s) _pure_;

const char* automount_state_to_string(AutomountState i) _const_;
AutomountState automount_state_from_string(const char *s) _pure_;

const char* device_state_to_string(DeviceState i) _const_;
DeviceState device_state_from_string(const char *s) _pure_;

const char* mount_state_to_string(MountState i) _const_;
MountState mount_state_from_string(const char *s) _pure_;

const char* path_state_to_string(PathState i) _const_;
PathState path_state_from_string(const char *s) _pure_;

const char* scope_state_to_string(ScopeState i) _const_;
ScopeState scope_state_from_string(const char *s) _pure_;

const char* service_state_to_string(ServiceState i) _const_;
ServiceState service_state_from_string(const char *s) _pure_;

const char* slice_state_to_string(SliceState i) _const_;
SliceState slice_state_from_string(const char *s) _pure_;

const char* socket_state_to_string(SocketState i) _const_;
SocketState socket_state_from_string(const char *s) _pure_;

const char* swap_state_to_string(SwapState i) _const_;
SwapState swap_state_from_string(const char *s) _pure_;

const char* target_state_to_string(TargetState i) _const_;
TargetState target_state_from_string(const char *s) _pure_;

const char *timer_state_to_string(TimerState i) _const_;
TimerState timer_state_from_string(const char *s) _pure_;

const char *unit_dependency_to_string(UnitDependency i) _const_;
UnitDependency unit_dependency_from_string(const char *s) _pure_;

const char* notify_access_to_string(NotifyAccess i) _const_;
NotifyAccess notify_access_from_string(const char *s) _pure_;

SpecialGlyph unit_active_state_to_glyph(UnitActiveState state);
