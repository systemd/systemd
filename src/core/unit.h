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
#include <stdlib.h>
#include <unistd.h>

typedef struct Unit Unit;
typedef struct UnitVTable UnitVTable;
typedef enum UnitActiveState UnitActiveState;
typedef enum UnitDependency UnitDependency;
typedef struct UnitRef UnitRef;
typedef struct UnitStatusMessageFormats UnitStatusMessageFormats;

#include "sd-event.h"
#include "set.h"
#include "util.h"
#include "list.h"
#include "socket-util.h"
#include "execute.h"
#include "cgroup.h"
#include "condition.h"
#include "install.h"
#include "unit-name.h"

enum UnitActiveState {
        UNIT_ACTIVE,
        UNIT_RELOADING,
        UNIT_INACTIVE,
        UNIT_FAILED,
        UNIT_ACTIVATING,
        UNIT_DEACTIVATING,
        _UNIT_ACTIVE_STATE_MAX,
        _UNIT_ACTIVE_STATE_INVALID = -1
};

static inline bool UNIT_IS_ACTIVE_OR_RELOADING(UnitActiveState t) {
        return t == UNIT_ACTIVE || t == UNIT_RELOADING;
}

static inline bool UNIT_IS_ACTIVE_OR_ACTIVATING(UnitActiveState t) {
        return t == UNIT_ACTIVE || t == UNIT_ACTIVATING || t == UNIT_RELOADING;
}

static inline bool UNIT_IS_INACTIVE_OR_DEACTIVATING(UnitActiveState t) {
        return t == UNIT_INACTIVE || t == UNIT_FAILED || t == UNIT_DEACTIVATING;
}

static inline bool UNIT_IS_INACTIVE_OR_FAILED(UnitActiveState t) {
        return t == UNIT_INACTIVE || t == UNIT_FAILED;
}

enum UnitDependency {
        /* Positive dependencies */
        UNIT_REQUIRES,
        UNIT_REQUIRES_OVERRIDABLE,
        UNIT_REQUISITE,
        UNIT_REQUISITE_OVERRIDABLE,
        UNIT_WANTS,
        UNIT_BINDS_TO,
        UNIT_PART_OF,

        /* Inverse of the above */
        UNIT_REQUIRED_BY,             /* inverse of 'requires' and 'requisite' is 'required_by' */
        UNIT_REQUIRED_BY_OVERRIDABLE, /* inverse of 'requires_overridable' and 'requisite_overridable' is 'soft_required_by' */
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
};

#include "manager.h"
#include "job.h"

struct UnitRef {
        /* Keeps tracks of references to a unit. This is useful so
         * that we can merge two units if necessary and correct all
         * references to them */

        Unit* unit;
        LIST_FIELDS(UnitRef, refs);
};

struct Unit {
        Manager *manager;

        UnitType type;
        UnitLoadState load_state;
        Unit *merged_into;

        char *id; /* One name is special because we use it for identification. Points to an entry in the names set */
        char *instance;

        Set *names;
        Set *dependencies[_UNIT_DEPENDENCY_MAX];

        char **requires_mounts_for;

        char *description;
        char **documentation;

        char *fragment_path; /* if loaded from a config file this is the primary path to it */
        char *source_path; /* if converted, the source file */
        char **dropin_paths;
        usec_t fragment_mtime;
        usec_t source_mtime;
        usec_t dropin_mtime;

        /* If there is something to do with this unit, then this is the installed job for it */
        Job *job;

        /* JOB_NOP jobs are special and can be installed without disturbing the real job. */
        Job *nop_job;

        usec_t job_timeout;

        /* References to this */
        LIST_HEAD(UnitRef, refs);

        /* Conditions to check */
        LIST_HEAD(Condition, conditions);

        dual_timestamp condition_timestamp;

        dual_timestamp inactive_exit_timestamp;
        dual_timestamp active_enter_timestamp;
        dual_timestamp active_exit_timestamp;
        dual_timestamp inactive_enter_timestamp;

        /* Counterparts in the cgroup filesystem */
        char *cgroup_path;
        CGroupControllerMask cgroup_realized_mask;
        CGroupControllerMask cgroup_subtree_mask;
        CGroupControllerMask cgroup_members_mask;

        UnitRef slice;

        /* Per type list */
        LIST_FIELDS(Unit, units_by_type);

        /* All units which have requires_mounts_for set */
        LIST_FIELDS(Unit, has_requires_mounts_for);

        /* Load queue */
        LIST_FIELDS(Unit, load_queue);

        /* D-Bus queue */
        LIST_FIELDS(Unit, dbus_queue);

        /* Cleanup queue */
        LIST_FIELDS(Unit, cleanup_queue);

        /* GC queue */
        LIST_FIELDS(Unit, gc_queue);

        /* CGroup realize members queue */
        LIST_FIELDS(Unit, cgroup_queue);

        /* PIDs we keep an eye on. Note that a unit might have many
         * more, but these are the ones we care enough about to
         * process SIGCHLD for */
        Set *pids;

        /* Used during GC sweeps */
        unsigned gc_marker;

        /* When deserializing, temporarily store the job type for this
         * unit here, if there was a job scheduled.
         * Only for deserializing from a legacy version. New style uses full
         * serialized jobs. */
        int deserialized_job; /* This is actually of type JobType */

        /* Error code when we didn't manage to load the unit (negative) */
        int load_error;

        /* Cached unit file state */
        UnitFileState unit_file_state;

        /* Garbage collect us we nobody wants or requires us anymore */
        bool stop_when_unneeded;

        /* Create default dependencies */
        bool default_dependencies;

        /* Refuse manual starting, allow starting only indirectly via dependency. */
        bool refuse_manual_start;

        /* Don't allow the user to stop this unit manually, allow stopping only indirectly via dependency. */
        bool refuse_manual_stop;

        /* Allow isolation requests */
        bool allow_isolate;

        /* How to start OnFailure units */
        JobMode on_failure_job_mode;

        /* Ignore this unit when isolating */
        bool ignore_on_isolate;

        /* Ignore this unit when snapshotting */
        bool ignore_on_snapshot;

        /* Did the last condition check succeed? */
        bool condition_result;

        /* Is this a transient unit? */
        bool transient;

        bool in_load_queue:1;
        bool in_dbus_queue:1;
        bool in_cleanup_queue:1;
        bool in_gc_queue:1;
        bool in_cgroup_queue:1;

        bool sent_dbus_new_signal:1;

        bool no_gc:1;

        bool in_audit:1;

        bool cgroup_realized:1;
        bool cgroup_members_mask_valid:1;
        bool cgroup_subtree_mask_valid:1;
};

struct UnitStatusMessageFormats {
        const char *starting_stopping[2];
        const char *finished_start_job[_JOB_RESULT_MAX];
        const char *finished_stop_job[_JOB_RESULT_MAX];
};

typedef enum UnitSetPropertiesMode {
        UNIT_CHECK = 0,
        UNIT_RUNTIME = 1,
        UNIT_PERSISTENT = 2,
} UnitSetPropertiesMode;

#include "service.h"
#include "socket.h"
#include "busname.h"
#include "target.h"
#include "snapshot.h"
#include "device.h"
#include "mount.h"
#include "automount.h"
#include "swap.h"
#include "timer.h"
#include "path.h"
#include "slice.h"
#include "scope.h"

struct UnitVTable {
        /* How much memory does an object of this unit type need */
        size_t object_size;

        /* If greater than 0, the offset into the object where
         * ExecContext is found, if the unit type has that */
        size_t exec_context_offset;

        /* If greater than 0, the offset into the object where
         * CGroupContext is found, if the unit type has that */
        size_t cgroup_context_offset;

        /* If greater than 0, the offset into the object where
         * KillContext is found, if the unit type has that */
        size_t kill_context_offset;

        /* If greater than 0, the offset into the object where the
         * pointer to ExecRuntime is found, if the unit type has
         * that */
        size_t exec_runtime_offset;

        /* The name of the configuration file section with the private settings of this unit*/
        const char *private_section;

        /* Config file sections this unit type understands, separated
         * by NUL chars */
        const char *sections;

        /* This should reset all type-specific variables. This should
         * not allocate memory, and is called with zero-initialized
         * data. It should hence only initialize variables that need
         * to be set != 0. */
        void (*init)(Unit *u);

        /* This should free all type-specific variables. It should be
         * idempotent. */
        void (*done)(Unit *u);

        /* Actually load data from disk. This may fail, and should set
         * load_state to UNIT_LOADED, UNIT_MERGED or leave it at
         * UNIT_STUB if no configuration could be found. */
        int (*load)(Unit *u);

        /* If a lot of units got created via enumerate(), this is
         * where to actually set the state and call unit_notify(). */
        int (*coldplug)(Unit *u);

        void (*dump)(Unit *u, FILE *f, const char *prefix);

        int (*start)(Unit *u);
        int (*stop)(Unit *u);
        int (*reload)(Unit *u);

        int (*kill)(Unit *u, KillWho w, int signo, sd_bus_error *error);

        bool (*can_reload)(Unit *u);

        /* Write all data that cannot be restored from other sources
         * away using unit_serialize_item() */
        int (*serialize)(Unit *u, FILE *f, FDSet *fds);

        /* Restore one item from the serialization */
        int (*deserialize_item)(Unit *u, const char *key, const char *data, FDSet *fds);

        /* Try to match up fds with what we need for this unit */
        int (*distribute_fds)(Unit *u, FDSet *fds);

        /* Boils down the more complex internal state of this unit to
         * a simpler one that the engine can understand */
        UnitActiveState (*active_state)(Unit *u);

        /* Returns the substate specific to this unit type as
         * string. This is purely information so that we can give the
         * user a more fine grained explanation in which actual state a
         * unit is in. */
        const char* (*sub_state_to_string)(Unit *u);

        /* Return true when there is reason to keep this entry around
         * even nothing references it and it isn't active in any
         * way */
        bool (*check_gc)(Unit *u);

        /* Return true when this unit is suitable for snapshotting */
        bool (*check_snapshot)(Unit *u);

        /* Invoked on every child that died */
        void (*sigchld_event)(Unit *u, pid_t pid, int code, int status);

        /* Reset failed state if we are in failed state */
        void (*reset_failed)(Unit *u);

        /* Called whenever any of the cgroups this unit watches for
         * ran empty */
        void (*notify_cgroup_empty)(Unit *u);

        /* Called whenever a process of this unit sends us a message */
        void (*notify_message)(Unit *u, pid_t pid, char **tags);

        /* Called whenever a name this Unit registered for comes or
         * goes away. */
        void (*bus_name_owner_change)(Unit *u, const char *name, const char *old_owner, const char *new_owner);

        /* Called for each property that is being set */
        int (*bus_set_property)(Unit *u, const char *name, sd_bus_message *message, UnitSetPropertiesMode mode, sd_bus_error *error);

        /* Called after at least one property got changed to apply the necessary change */
        int (*bus_commit_properties)(Unit *u);

        /* Return the unit this unit is following */
        Unit *(*following)(Unit *u);

        /* Return the set of units that are following each other */
        int (*following_set)(Unit *u, Set **s);

        /* Invoked each time a unit this unit is triggering changes
         * state or gains/loses a job */
        void (*trigger_notify)(Unit *u, Unit *trigger);

        /* Called whenever CLOCK_REALTIME made a jump */
        void (*time_change)(Unit *u);

        int (*get_timeout)(Unit *u, uint64_t *timeout);

        /* This is called for each unit type and should be used to
         * enumerate existing devices and load them. However,
         * everything that is loaded here should still stay in
         * inactive state. It is the job of the coldplug() call above
         * to put the units into the initial state.  */
        int (*enumerate)(Manager *m);

        /* Type specific cleanups. */
        void (*shutdown)(Manager *m);

        /* The interface name */
        const char *bus_interface;

        /* The bus vtable */
        const sd_bus_vtable *bus_vtable;

        /* The strings to print in status messages */
        UnitStatusMessageFormats status_message_formats;

        /* Can units of this type have multiple names? */
        bool no_alias:1;

        /* Instances make no sense for this type */
        bool no_instances:1;

        /* Exclude from automatic gc */
        bool no_gc:1;

        /* True if transient units of this type are OK */
        bool can_transient:1;
};

extern const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX];

#define UNIT_VTABLE(u) unit_vtable[(u)->type]

/* For casting a unit into the various unit types */
#define DEFINE_CAST(UPPERCASE, MixedCase)                               \
        static inline MixedCase* UPPERCASE(Unit *u) {                   \
                if (_unlikely_(!u || u->type != UNIT_##UPPERCASE))      \
                        return NULL;                                    \
                                                                        \
                return (MixedCase*) u;                                  \
        }

/* For casting the various unit types into a unit */
#define UNIT(u) (&(u)->meta)

#define UNIT_TRIGGER(u) ((Unit*) set_first((u)->dependencies[UNIT_TRIGGERS]))

DEFINE_CAST(SERVICE, Service);
DEFINE_CAST(SOCKET, Socket);
DEFINE_CAST(BUSNAME, BusName);
DEFINE_CAST(TARGET, Target);
DEFINE_CAST(SNAPSHOT, Snapshot);
DEFINE_CAST(DEVICE, Device);
DEFINE_CAST(MOUNT, Mount);
DEFINE_CAST(AUTOMOUNT, Automount);
DEFINE_CAST(SWAP, Swap);
DEFINE_CAST(TIMER, Timer);
DEFINE_CAST(PATH, Path);
DEFINE_CAST(SLICE, Slice);
DEFINE_CAST(SCOPE, Scope);

Unit *unit_new(Manager *m, size_t size);
void unit_free(Unit *u);

int unit_add_name(Unit *u, const char *name);

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other, bool add_reference);
int unit_add_two_dependencies(Unit *u, UnitDependency d, UnitDependency e, Unit *other, bool add_reference);

int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name, const char *filename, bool add_reference);
int unit_add_two_dependencies_by_name(Unit *u, UnitDependency d, UnitDependency e, const char *name, const char *path, bool add_reference);

int unit_add_dependency_by_name_inverse(Unit *u, UnitDependency d, const char *name, const char *filename, bool add_reference);
int unit_add_two_dependencies_by_name_inverse(Unit *u, UnitDependency d, UnitDependency e, const char *name, const char *path, bool add_reference);

int unit_add_exec_dependencies(Unit *u, ExecContext *c);

int unit_choose_id(Unit *u, const char *name);
int unit_set_description(Unit *u, const char *description);

bool unit_check_gc(Unit *u);

void unit_add_to_load_queue(Unit *u);
void unit_add_to_dbus_queue(Unit *u);
void unit_add_to_cleanup_queue(Unit *u);
void unit_add_to_gc_queue(Unit *u);

int unit_merge(Unit *u, Unit *other);
int unit_merge_by_name(Unit *u, const char *other);

Unit *unit_follow_merge(Unit *u) _pure_;

int unit_load_fragment_and_dropin(Unit *u);
int unit_load_fragment_and_dropin_optional(Unit *u);
int unit_load(Unit *unit);

int unit_add_default_slice(Unit *u, CGroupContext *c);

const char *unit_description(Unit *u) _pure_;

bool unit_has_name(Unit *u, const char *name);

UnitActiveState unit_active_state(Unit *u);

const char* unit_sub_state_to_string(Unit *u);

void unit_dump(Unit *u, FILE *f, const char *prefix);

bool unit_can_reload(Unit *u) _pure_;
bool unit_can_start(Unit *u) _pure_;
bool unit_can_isolate(Unit *u) _pure_;

int unit_start(Unit *u);
int unit_stop(Unit *u);
int unit_reload(Unit *u);

int unit_kill(Unit *u, KillWho w, int signo, sd_bus_error *error);
int unit_kill_common(Unit *u, KillWho who, int signo, pid_t main_pid, pid_t control_pid, sd_bus_error *error);

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns, bool reload_success);

int unit_watch_pid(Unit *u, pid_t pid);
void unit_unwatch_pid(Unit *u, pid_t pid);
int unit_watch_all_pids(Unit *u);
void unit_unwatch_all_pids(Unit *u);

void unit_tidy_watch_pids(Unit *u, pid_t except1, pid_t except2);

int unit_watch_bus_name(Unit *u, const char *name);
void unit_unwatch_bus_name(Unit *u, const char *name);

bool unit_job_is_applicable(Unit *u, JobType j);

int set_unit_path(const char *p);

char *unit_dbus_path(Unit *u);

int unit_load_related_unit(Unit *u, const char *type, Unit **_found);

bool unit_can_serialize(Unit *u) _pure_;
int unit_serialize(Unit *u, FILE *f, FDSet *fds, bool serialize_jobs);
void unit_serialize_item_format(Unit *u, FILE *f, const char *key, const char *value, ...) _printf_(4,5);
void unit_serialize_item(Unit *u, FILE *f, const char *key, const char *value);
int unit_deserialize(Unit *u, FILE *f, FDSet *fds);

int unit_add_node_link(Unit *u, const char *what, bool wants);

int unit_coldplug(Unit *u);

void unit_status_printf(Unit *u, const char *status, const char *unit_status_msg_format) _printf_(3, 0);

bool unit_need_daemon_reload(Unit *u);

void unit_reset_failed(Unit *u);

Unit *unit_following(Unit *u);
int unit_following_set(Unit *u, Set **s);

const char *unit_slice_name(Unit *u);

bool unit_stop_pending(Unit *u) _pure_;
bool unit_inactive_or_pending(Unit *u) _pure_;
bool unit_active_or_pending(Unit *u);

int unit_add_default_target_dependency(Unit *u, Unit *target);

char *unit_default_cgroup_path(Unit *u);

void unit_start_on_failure(Unit *u);
void unit_trigger_notify(Unit *u);

UnitFileState unit_get_unit_file_state(Unit *u);

Unit* unit_ref_set(UnitRef *ref, Unit *u);
void unit_ref_unset(UnitRef *ref);

#define UNIT_DEREF(ref) ((ref).unit)
#define UNIT_ISSET(ref) (!!(ref).unit)

int unit_patch_contexts(Unit *u);

ExecContext *unit_get_exec_context(Unit *u) _pure_;
KillContext *unit_get_kill_context(Unit *u) _pure_;
CGroupContext *unit_get_cgroup_context(Unit *u) _pure_;

ExecRuntime *unit_get_exec_runtime(Unit *u) _pure_;

int unit_setup_exec_runtime(Unit *u);

int unit_write_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *data);
int unit_write_drop_in_format(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *format, ...) _printf_(4,5);

int unit_write_drop_in_private(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *data);
int unit_write_drop_in_private_format(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *format, ...) _printf_(4,5);

int unit_remove_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name);

int unit_kill_context(Unit *u, KillContext *c, bool sigkill, pid_t main_pid, pid_t control_pid, bool main_pid_alien);

int unit_make_transient(Unit *u);

int unit_require_mounts_for(Unit *u, const char *path);

const char *unit_active_state_to_string(UnitActiveState i) _const_;
UnitActiveState unit_active_state_from_string(const char *s) _pure_;

const char *unit_dependency_to_string(UnitDependency i) _const_;
UnitDependency unit_dependency_from_string(const char *s) _pure_;

/* Macros which append UNIT= or USER_UNIT= to the message */

#define log_full_unit(level, unit, ...) log_meta_object(level, __FILE__, __LINE__, __func__, getpid() == 1 ? "UNIT=" : "USER_UNIT=", unit, __VA_ARGS__)
#define log_debug_unit(unit, ...)       log_full_unit(LOG_DEBUG, unit, __VA_ARGS__)
#define log_info_unit(unit, ...)        log_full_unit(LOG_INFO, unit, __VA_ARGS__)
#define log_notice_unit(unit, ...)      log_full_unit(LOG_NOTICE, unit, __VA_ARGS__)
#define log_warning_unit(unit, ...)     log_full_unit(LOG_WARNING, unit, __VA_ARGS__)
#define log_error_unit(unit, ...)       log_full_unit(LOG_ERR, unit, __VA_ARGS__)

#define log_struct_unit(level, unit, ...) log_struct(level, getpid() == 1 ? "UNIT=%s" : "USER_UNIT=%s", unit, __VA_ARGS__)
