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

#include <stdbool.h>

#include "macro.h"

#define UNIT_NAME_MAX 256

typedef enum UnitType {
        UNIT_SERVICE = 0,
        UNIT_SOCKET,
        UNIT_BUSNAME,
        UNIT_TARGET,
        UNIT_SNAPSHOT,
        UNIT_DEVICE,
        UNIT_MOUNT,
        UNIT_AUTOMOUNT,
        UNIT_SWAP,
        UNIT_TIMER,
        UNIT_PATH,
        UNIT_SLICE,
        UNIT_SCOPE,
        _UNIT_TYPE_MAX,
        _UNIT_TYPE_INVALID = -1
} UnitType;

typedef enum UnitLoadState {
        UNIT_STUB = 0,
        UNIT_LOADED,
        UNIT_NOT_FOUND,
        UNIT_ERROR,
        UNIT_MERGED,
        UNIT_MASKED,
        _UNIT_LOAD_STATE_MAX,
        _UNIT_LOAD_STATE_INVALID = -1
} UnitLoadState;

typedef enum UnitActiveState {
        UNIT_ACTIVE,
        UNIT_RELOADING,
        UNIT_INACTIVE,
        UNIT_FAILED,
        UNIT_ACTIVATING,
        UNIT_DEACTIVATING,
        _UNIT_ACTIVE_STATE_MAX,
        _UNIT_ACTIVE_STATE_INVALID = -1
} UnitActiveState;

typedef enum AutomountState {
        AUTOMOUNT_DEAD,
        AUTOMOUNT_WAITING,
        AUTOMOUNT_RUNNING,
        AUTOMOUNT_FAILED,
        _AUTOMOUNT_STATE_MAX,
        _AUTOMOUNT_STATE_INVALID = -1
} AutomountState;

typedef enum BusNameState {
        BUSNAME_DEAD,
        BUSNAME_MAKING,
        BUSNAME_REGISTERED,
        BUSNAME_LISTENING,
        BUSNAME_RUNNING,
        BUSNAME_SIGTERM,
        BUSNAME_SIGKILL,
        BUSNAME_FAILED,
        _BUSNAME_STATE_MAX,
        _BUSNAME_STATE_INVALID = -1
} BusNameState;

/* We simply watch devices, we cannot plug/unplug them. That
 * simplifies the state engine greatly */
typedef enum DeviceState {
        DEVICE_DEAD,
        DEVICE_TENTATIVE, /* mounted or swapped, but not (yet) announced by udev */
        DEVICE_PLUGGED,   /* announced by udev */
        _DEVICE_STATE_MAX,
        _DEVICE_STATE_INVALID = -1
} DeviceState;

typedef enum MountState {
        MOUNT_DEAD,
        MOUNT_MOUNTING,               /* /usr/bin/mount is running, but the mount is not done yet. */
        MOUNT_MOUNTING_DONE,          /* /usr/bin/mount is running, and the mount is done. */
        MOUNT_MOUNTED,
        MOUNT_REMOUNTING,
        MOUNT_UNMOUNTING,
        MOUNT_MOUNTING_SIGTERM,
        MOUNT_MOUNTING_SIGKILL,
        MOUNT_REMOUNTING_SIGTERM,
        MOUNT_REMOUNTING_SIGKILL,
        MOUNT_UNMOUNTING_SIGTERM,
        MOUNT_UNMOUNTING_SIGKILL,
        MOUNT_FAILED,
        _MOUNT_STATE_MAX,
        _MOUNT_STATE_INVALID = -1
} MountState;

typedef enum PathState {
        PATH_DEAD,
        PATH_WAITING,
        PATH_RUNNING,
        PATH_FAILED,
        _PATH_STATE_MAX,
        _PATH_STATE_INVALID = -1
} PathState;

typedef enum ScopeState {
        SCOPE_DEAD,
        SCOPE_RUNNING,
        SCOPE_ABANDONED,
        SCOPE_STOP_SIGTERM,
        SCOPE_STOP_SIGKILL,
        SCOPE_FAILED,
        _SCOPE_STATE_MAX,
        _SCOPE_STATE_INVALID = -1
} ScopeState;

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_START_PRE,
        SERVICE_START,
        SERVICE_START_POST,
        SERVICE_RUNNING,
        SERVICE_EXITED,            /* Nothing is running anymore, but RemainAfterExit is true hence this is OK */
        SERVICE_RELOAD,
        SERVICE_STOP,              /* No STOP_PRE state, instead just register multiple STOP executables */
        SERVICE_STOP_SIGABRT,      /* Watchdog timeout */
        SERVICE_STOP_SIGTERM,
        SERVICE_STOP_SIGKILL,
        SERVICE_STOP_POST,
        SERVICE_FINAL_SIGTERM,     /* In case the STOP_POST executable hangs, we shoot that down, too */
        SERVICE_FINAL_SIGKILL,
        SERVICE_FAILED,
        SERVICE_AUTO_RESTART,
        _SERVICE_STATE_MAX,
        _SERVICE_STATE_INVALID = -1
} ServiceState;

typedef enum SliceState {
        SLICE_DEAD,
        SLICE_ACTIVE,
        _SLICE_STATE_MAX,
        _SLICE_STATE_INVALID = -1
} SliceState;

typedef enum SnapshotState {
        SNAPSHOT_DEAD,
        SNAPSHOT_ACTIVE,
        _SNAPSHOT_STATE_MAX,
        _SNAPSHOT_STATE_INVALID = -1
} SnapshotState;

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
        _SOCKET_STATE_MAX,
        _SOCKET_STATE_INVALID = -1
} SocketState;

typedef enum SwapState {
        SWAP_DEAD,
        SWAP_ACTIVATING,               /* /sbin/swapon is running, but the swap not yet enabled. */
        SWAP_ACTIVATING_DONE,          /* /sbin/swapon is running, and the swap is done. */
        SWAP_ACTIVE,
        SWAP_DEACTIVATING,
        SWAP_ACTIVATING_SIGTERM,
        SWAP_ACTIVATING_SIGKILL,
        SWAP_DEACTIVATING_SIGTERM,
        SWAP_DEACTIVATING_SIGKILL,
        SWAP_FAILED,
        _SWAP_STATE_MAX,
        _SWAP_STATE_INVALID = -1
} SwapState;


typedef enum TargetState {
        TARGET_DEAD,
        TARGET_ACTIVE,
        _TARGET_STATE_MAX,
        _TARGET_STATE_INVALID = -1
} TargetState;

typedef enum TimerState {
        TIMER_DEAD,
        TIMER_WAITING,
        TIMER_RUNNING,
        TIMER_ELAPSED,
        TIMER_FAILED,
        _TIMER_STATE_MAX,
        _TIMER_STATE_INVALID = -1
} TimerState;

typedef enum UnitDependency {
        /* Positive dependencies */
        UNIT_REQUIRES,
        UNIT_REQUIRES_OVERRIDABLE,
        UNIT_REQUISITE,
        UNIT_REQUISITE_OVERRIDABLE,
        UNIT_WANTS,
        UNIT_BINDS_TO,
        UNIT_PART_OF,

        /* Inverse of the above */
        UNIT_REQUIRED_BY,             /* inverse of 'requires' is 'required_by' */
        UNIT_REQUIRED_BY_OVERRIDABLE, /* inverse of 'requires_overridable' is 'required_by_overridable' */
        UNIT_REQUISITE_OF,            /* inverse of 'requisite' is 'requisite_of' */
        UNIT_REQUISITE_OF_OVERRIDABLE,/* inverse of 'requisite_overridable' is 'requisite_of_overridable' */
        UNIT_WANTED_BY,               /* inverse of 'wants' */
        UNIT_BOUND_BY,                /* inverse of 'binds_to' */
        UNIT_CONSISTS_OF,             /* inverse of 'part_of' */

        /* Negative dependencies */
        UNIT_CONFLICTS,               /* inverse of 'conflicts' is 'conflicted_by' */
        UNIT_CONFLICTED_BY,

        /* Order */
        UNIT_BEFORE,                  /* inverse of 'before' is 'after' and vice versa */
        UNIT_AFTER,

        /* On Failure */
        UNIT_ON_FAILURE,

        /* Triggers (i.e. a socket triggers a service) */
        UNIT_TRIGGERS,
        UNIT_TRIGGERED_BY,

        /* Propagate reloads */
        UNIT_PROPAGATES_RELOAD_TO,
        UNIT_RELOAD_PROPAGATED_FROM,

        /* Joins namespace of */
        UNIT_JOINS_NAMESPACE_OF,

        /* Reference information for GC logic */
        UNIT_REFERENCES,              /* Inverse of 'references' is 'referenced_by' */
        UNIT_REFERENCED_BY,

        _UNIT_DEPENDENCY_MAX,
        _UNIT_DEPENDENCY_INVALID = -1
} UnitDependency;

typedef enum UnitNameFlags {
        UNIT_NAME_PLAIN = 1,      /* Allow foo.service */
        UNIT_NAME_INSTANCE = 2,   /* Allow foo@bar.service */
        UNIT_NAME_TEMPLATE = 4,   /* Allow foo@.service */
        UNIT_NAME_ANY = UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE,
} UnitNameFlags;

bool unit_name_is_valid(const char *n, UnitNameFlags flags) _pure_;
bool unit_prefix_is_valid(const char *p) _pure_;
bool unit_instance_is_valid(const char *i) _pure_;
bool unit_suffix_is_valid(const char *s) _pure_;

static inline int unit_prefix_and_instance_is_valid(const char *p) {
        /* For prefix+instance and instance the same rules apply */
        return unit_instance_is_valid(p);
}

int unit_name_to_prefix(const char *n, char **prefix);
int unit_name_to_instance(const char *n, char **instance);
int unit_name_to_prefix_and_instance(const char *n, char **ret);

UnitType unit_name_to_type(const char *n) _pure_;

int unit_name_change_suffix(const char *n, const char *suffix, char **ret);

int unit_name_build(const char *prefix, const char *instance, const char *suffix, char **ret);

char *unit_name_escape(const char *f);
int unit_name_unescape(const char *f, char **ret);
int unit_name_path_escape(const char *f, char **ret);
int unit_name_path_unescape(const char *f, char **ret);

int unit_name_replace_instance(const char *f, const char *i, char **ret);

int unit_name_template(const char *f, char **ret);

int unit_name_from_path(const char *path, const char *suffix, char **ret);
int unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix, char **ret);
int unit_name_to_path(const char *name, char **ret);

char *unit_dbus_path_from_name(const char *name);
int unit_name_from_dbus_path(const char *path, char **name);

const char* unit_dbus_interface_from_type(UnitType t);
const char *unit_dbus_interface_from_name(const char *name);

typedef enum UnitNameMangle {
        UNIT_NAME_NOGLOB,
        UNIT_NAME_GLOB,
} UnitNameMangle;

int unit_name_mangle_with_suffix(const char *name, UnitNameMangle allow_globs, const char *suffix, char **ret);

static inline int unit_name_mangle(const char *name, UnitNameMangle allow_globs, char **ret) {
        return unit_name_mangle_with_suffix(name, allow_globs, ".service", ret);
}

int slice_build_parent_slice(const char *slice, char **ret);
int slice_build_subslice(const char *slice, const char*name, char **subslice);
bool slice_name_is_valid(const char *name);

const char *unit_type_to_string(UnitType i) _const_;
UnitType unit_type_from_string(const char *s) _pure_;

const char *unit_load_state_to_string(UnitLoadState i) _const_;
UnitLoadState unit_load_state_from_string(const char *s) _pure_;

const char *unit_active_state_to_string(UnitActiveState i) _const_;
UnitActiveState unit_active_state_from_string(const char *s) _pure_;

const char* automount_state_to_string(AutomountState i) _const_;
AutomountState automount_state_from_string(const char *s) _pure_;

const char* busname_state_to_string(BusNameState i) _const_;
BusNameState busname_state_from_string(const char *s) _pure_;

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

const char* snapshot_state_to_string(SnapshotState i) _const_;
SnapshotState snapshot_state_from_string(const char *s) _pure_;

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
