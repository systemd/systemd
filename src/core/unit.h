/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "core-forward.h"
#include "emergency-action.h"
#include "execute.h"
#include "hashmap.h"
#include "install.h"
#include "iterator.h"
#include "job.h"
#include "list.h"
#include "log.h"
#include "log-context.h"
#include "ratelimit.h"
#include "time-util.h"
#include "unit-def.h"
#include "unit-dependency-atom.h"
#include "unit-file.h"

typedef enum UnitMountDependencyType {
        UNIT_MOUNT_WANTS,
        UNIT_MOUNT_REQUIRES,
        _UNIT_MOUNT_DEPENDENCY_TYPE_MAX,
        _UNIT_MOUNT_DEPENDENCY_TYPE_INVALID = -EINVAL,
} UnitMountDependencyType;

typedef enum KillOperation {
        KILL_TERMINATE,
        KILL_TERMINATE_AND_LOG,
        KILL_RESTART,
        KILL_KILL,
        KILL_WATCHDOG,
        _KILL_OPERATION_MAX,
        _KILL_OPERATION_INVALID = -EINVAL,
} KillOperation;

typedef enum CollectMode {
        COLLECT_INACTIVE,
        COLLECT_INACTIVE_OR_FAILED,
        _COLLECT_MODE_MAX,
        _COLLECT_MODE_INVALID = -EINVAL,
} CollectMode;

typedef enum OOMPolicy {
        OOM_CONTINUE,          /* The kernel or systemd-oomd kills the process it wants to kill, and that's it */
        OOM_STOP,              /* The kernel or systemd-oomd kills the process it wants to kill, and we stop the unit */
        OOM_KILL,              /* The kernel or systemd-oomd kills the process it wants to kill, and all others in the unit, and we stop the unit */
        _OOM_POLICY_MAX,
        _OOM_POLICY_INVALID = -EINVAL,
} OOMPolicy;

typedef enum StatusType {
        STATUS_TYPE_EPHEMERAL,   /* ordered by severity! Do not break order */
        STATUS_TYPE_NORMAL,
        STATUS_TYPE_NOTICE,
        STATUS_TYPE_EMERGENCY,
        _STATUS_TYPE_MAX,
        _STATUS_TYPE_INVALID = -EINVAL,
} StatusType;

static inline bool UNIT_IS_ACTIVE_OR_RELOADING(UnitActiveState t) {
        return IN_SET(t, UNIT_ACTIVE, UNIT_RELOADING, UNIT_REFRESHING);
}

static inline bool UNIT_IS_ACTIVE_OR_ACTIVATING(UnitActiveState t) {
        return IN_SET(t, UNIT_ACTIVE, UNIT_ACTIVATING, UNIT_RELOADING, UNIT_REFRESHING);
}

static inline bool UNIT_IS_INACTIVE_OR_DEACTIVATING(UnitActiveState t) {
        return IN_SET(t, UNIT_INACTIVE, UNIT_FAILED, UNIT_DEACTIVATING);
}

static inline bool UNIT_IS_INACTIVE_OR_FAILED(UnitActiveState t) {
        return IN_SET(t, UNIT_INACTIVE, UNIT_FAILED);
}

static inline bool UNIT_IS_LOAD_COMPLETE(UnitLoadState t) {
        return t >= 0 && t < _UNIT_LOAD_STATE_MAX && !IN_SET(t, UNIT_STUB, UNIT_MERGED);
}

static inline bool UNIT_IS_LOAD_ERROR(UnitLoadState t) {
        return IN_SET(t, UNIT_NOT_FOUND, UNIT_BAD_SETTING, UNIT_ERROR);
}

/* Stores the 'reason' a dependency was created as a bit mask, i.e. due to which configuration source it came to be. We
 * use this so that we can selectively flush out parts of dependencies again. Note that the same dependency might be
 * created as a result of multiple "reasons", hence the bitmask. */
typedef enum UnitDependencyMask {
        /* Configured directly by the unit file, .wants/.requires symlink or drop-in, or as an immediate result of a
         * non-dependency option configured that way.  */
        UNIT_DEPENDENCY_FILE               = 1 << 0,

        /* As unconditional implicit dependency (not affected by unit configuration — except by the unit name and
         * type) */
        UNIT_DEPENDENCY_IMPLICIT           = 1 << 1,

        /* A dependency affected by DefaultDependencies=yes. Note that dependencies marked this way are conceptually
         * just a subset of UNIT_DEPENDENCY_FILE, as DefaultDependencies= is itself a unit file setting that can only
         * be set in unit files. We make this two separate bits only to help debugging how dependencies came to be. */
        UNIT_DEPENDENCY_DEFAULT            = 1 << 2,

        /* A dependency created from udev rules */
        UNIT_DEPENDENCY_UDEV               = 1 << 3,

        /* A dependency created because of some unit's RequiresMountsFor= setting */
        UNIT_DEPENDENCY_PATH               = 1 << 4,

        /* A dependency initially configured from the mount unit file however the dependency will be updated
         * from /proc/self/mountinfo as soon as the kernel will make the entry for that mount available in
         * the /proc file */
        UNIT_DEPENDENCY_MOUNT_FILE         = 1 << 5,

        /* A dependency created or updated because of data read from /proc/self/mountinfo */
        UNIT_DEPENDENCY_MOUNTINFO          = 1 << 6,

        /* A dependency created because of data read from /proc/swaps and no other configuration source */
        UNIT_DEPENDENCY_PROC_SWAP          = 1 << 7,

        /* A dependency for units in slices assigned by directly setting Slice= */
        UNIT_DEPENDENCY_SLICE_PROPERTY     = 1 << 8,

        _UNIT_DEPENDENCY_MASK_FULL         = (1 << 9) - 1,
} UnitDependencyMask;

/* The Unit's dependencies[] hashmaps use this structure as value. It has the same size as a void pointer, and thus can
 * be stored directly as hashmap value, without any indirection. Note that this stores two masks, as both the origin
 * and the destination of a dependency might have created it. */
typedef union UnitDependencyInfo {
        void *data;
        struct {
                UnitDependencyMask origin_mask:16;
                UnitDependencyMask destination_mask:16;
        } _packed_;
} UnitDependencyInfo;

/* Store information about why a unit was activated.
 * We start with trigger units (.path/.timer), eventually it will be expanded to include more metadata. */
typedef struct ActivationDetails {
        unsigned n_ref;
        UnitType trigger_unit_type;
        char *trigger_unit_name;
} ActivationDetails;

/* For casting an activation event into the various unit-specific types */
#define DEFINE_ACTIVATION_DETAILS_CAST(UPPERCASE, MixedCase, UNIT_TYPE)         \
        static inline MixedCase* UPPERCASE(const ActivationDetails *a) {              \
                if (_unlikely_(!a || a->trigger_unit_type != UNIT_##UNIT_TYPE)) \
                        return NULL;                                            \
                                                                                \
                return (MixedCase*) a;                                          \
        }

/* For casting the various unit types into a unit */
#define ACTIVATION_DETAILS(u)                                         \
        ({                                                            \
                typeof(u) _u_ = (u);                                  \
                ActivationDetails *_w_ = _u_ ? &(_u_)->meta : NULL;   \
                _w_;                                                  \
        })

ActivationDetails *activation_details_new(Unit *trigger_unit);
ActivationDetails *activation_details_ref(ActivationDetails *p);
ActivationDetails *activation_details_unref(ActivationDetails *p);
void activation_details_serialize(const ActivationDetails *details, FILE *f);
int activation_details_deserialize(const char *key, const char *value, ActivationDetails **details);
int activation_details_append_env(const ActivationDetails *details, char ***strv);
int activation_details_append_pair(const ActivationDetails *details, char ***strv);
DEFINE_TRIVIAL_CLEANUP_FUNC(ActivationDetails*, activation_details_unref);

typedef struct ActivationDetailsVTable {
        /* How much memory does an object of this activation type need */
        size_t object_size;

        /* This should reset all type-specific variables. This should not allocate memory, and is called
         * with zero-initialized data. It should hence only initialize variables that need to be set != 0. */
        void (*init)(ActivationDetails *details, Unit *trigger_unit);

        /* This should free all type-specific variables. It should be idempotent. */
        void (*done)(ActivationDetails *details);

        /* This should serialize all type-specific variables. */
        void (*serialize)(const ActivationDetails *details, FILE *f);

        /* This should deserialize all type-specific variables, one at a time. */
        int (*deserialize)(const char *key, const char *value, ActivationDetails **details);

        /* This should format the type-specific variables for the env block of the spawned service,
         * and return the number of added items. */
        int (*append_env)(const ActivationDetails *details, char ***strv);

        /* This should append type-specific variables as key/value pairs for the D-Bus property of the job,
         * and return the number of added pairs. */
        int (*append_pair)(const ActivationDetails *details, char ***strv);
} ActivationDetailsVTable;

extern const ActivationDetailsVTable * const activation_details_vtable[_UNIT_TYPE_MAX];

static inline const ActivationDetailsVTable* ACTIVATION_DETAILS_VTABLE(const ActivationDetails *a) {
        assert(a);
        assert(a->trigger_unit_type < _UNIT_TYPE_MAX);

        return activation_details_vtable[a->trigger_unit_type];
}

/* Newer LLVM versions don't like implicit casts from large pointer types to smaller enums, hence let's add
 * explicit type-safe helpers for that. */
static inline UnitDependency UNIT_DEPENDENCY_FROM_PTR(const void *p) {
        return PTR_TO_INT(p);
}

static inline void* UNIT_DEPENDENCY_TO_PTR(UnitDependency d) {
        return INT_TO_PTR(d);
}

typedef struct UnitRef {
        /* Keeps tracks of references to a unit. This is useful so
         * that we can merge two units if necessary and correct all
         * references to them */

        Unit *source, *target;
        LIST_FIELDS(UnitRef, refs_by_target);
} UnitRef;

/* The generic, dynamic definition of the unit */
typedef struct Unit {
        Manager *manager;

        UnitType type;
        UnitLoadState load_state;
        Unit *merged_into;

        char *id;   /* The one special name that we use for identification */
        char *instance;

        Set *aliases; /* All the other names. */

        /* For each dependency type we can look up another Hashmap with this, whose key is a Unit* object,
         * and whose value encodes why the dependency exists, using the UnitDependencyInfo type. i.e. a
         * Hashmap(UnitDependency → Hashmap(Unit* → UnitDependencyInfo)) */
        Hashmap *dependencies;
        uint64_t dependency_generation;

        /* Similar, for RequiresMountsFor= and WantsMountsFor= path dependencies. The key is the path, the
         * value the UnitDependencyInfo type */
        Hashmap *mounts_for[_UNIT_MOUNT_DEPENDENCY_TYPE_MAX];

        char *description;
        char **documentation;

        /* The SELinux context used for checking access to this unit read off the unit file at load time (do
         * not confuse with the selinux_context field in ExecContext which is the SELinux context we'll set
         * for processes) */
        char *access_selinux_context;

        char *fragment_path; /* if loaded from a config file this is the primary path to it */
        char *source_path; /* if converted, the source file */
        char **dropin_paths;

        usec_t fragment_not_found_timestamp_hash;
        usec_t fragment_mtime;
        usec_t source_mtime;
        usec_t dropin_mtime;

        /* If this is a transient unit we are currently writing, this is where we are writing it to */
        FILE *transient_file;

        /* Freezer state */
        sd_bus_message *pending_freezer_invocation;
        FreezerState freezer_state;

        /* Job timeout and action to take */
        EmergencyAction job_timeout_action;
        usec_t job_timeout;
        usec_t job_running_timeout;
        char *job_timeout_reboot_arg;

        /* If there is something to do with this unit, then this is the installed job for it */
        Job *job;

        /* JOB_NOP jobs are special and can be installed without disturbing the real job. */
        Job *nop_job;

        /* The slot used for watching NameOwnerChanged signals */
        sd_bus_slot *match_bus_slot;
        sd_bus_slot *get_name_owner_slot;

        /* References to this unit from clients */
        sd_bus_track *bus_track;
        char **deserialized_refs;

        /* References to this */
        LIST_HEAD(UnitRef, refs_by_target);

        /* Conditions to check */
        LIST_HEAD(Condition, conditions);
        LIST_HEAD(Condition, asserts);

        dual_timestamp condition_timestamp;
        dual_timestamp assert_timestamp;

        /* Updated whenever the low-level state changes */
        dual_timestamp state_change_timestamp;

        /* Updated whenever the (high-level) active state enters or leaves the active or inactive states */
        dual_timestamp inactive_exit_timestamp;
        dual_timestamp active_enter_timestamp;
        dual_timestamp active_exit_timestamp;
        dual_timestamp inactive_enter_timestamp;

        /* Per type list */
        LIST_FIELDS(Unit, units_by_type);

        /* Load queue */
        LIST_FIELDS(Unit, load_queue);

        /* D-Bus queue */
        LIST_FIELDS(Unit, dbus_queue);

        /* Cleanup queue */
        LIST_FIELDS(Unit, cleanup_queue);

        /* GC queue */
        LIST_FIELDS(Unit, gc_queue);

        /* CGroup realize members queue */
        LIST_FIELDS(Unit, cgroup_realize_queue);

        /* cgroup empty queue */
        LIST_FIELDS(Unit, cgroup_empty_queue);

        /* cgroup OOM queue */
        LIST_FIELDS(Unit, cgroup_oom_queue);

        /* Target dependencies queue */
        LIST_FIELDS(Unit, target_deps_queue);

        /* Queue of units with StopWhenUnneeded= set that shall be checked for clean-up. */
        LIST_FIELDS(Unit, stop_when_unneeded_queue);

        /* Queue of units that have an Uphold= dependency from some other unit, and should be checked for starting */
        LIST_FIELDS(Unit, start_when_upheld_queue);

        /* Queue of units that have a BindTo= dependency on some other unit, and should possibly be shut down */
        LIST_FIELDS(Unit, stop_when_bound_queue);

        /* Queue of units that should be checked if they can release resources now */
        LIST_FIELDS(Unit, release_resources_queue);

        /* Queue of units that should be informed when other units stop */
        LIST_FIELDS(Unit, stop_notify_queue);

        /* PIDs we keep an eye on. Note that a unit might have many more, but these are the ones we care
         * enough about to process SIGCHLD for */
        Set *pids; /* → PidRef* */

        /* Used in SIGCHLD and sd_notify() message event invocation logic to avoid that we dispatch the same event
         * multiple times on the same unit. */
        unsigned sigchldgen;
        unsigned notifygen;

        /* Used during GC sweeps */
        unsigned gc_marker;

        /* Error code when we didn't manage to load the unit (negative) */
        int load_error;

        /* Put a ratelimit on unit starting */
        RateLimit start_ratelimit;
        EmergencyAction start_limit_action;

        /* The unit has been marked for reload, restart, etc. Stored as 1u << marker1 | 1u << marker2. */
        unsigned markers;

        /* What to do on failure or success */
        EmergencyAction success_action, failure_action;
        int success_action_exit_status, failure_action_exit_status;
        char *reboot_arg;

        /* Make sure we never enter endless loops with the StopWhenUnneeded=, BindsTo=, Uphold= logic */
        RateLimit auto_start_stop_ratelimit;
        sd_event_source *auto_start_stop_event_source;

        /* Reference to a specific UID/GID */
        uid_t ref_uid;
        gid_t ref_gid;

        /* Cached unit file state and preset */
        UnitFileState unit_file_state;
        PresetAction unit_file_preset;

        /* How to start OnSuccess=/OnFailure= units */
        JobMode on_success_job_mode;
        JobMode on_failure_job_mode;

        /* If the job had a specific trigger that needs to be advertised (eg: a path unit), store it. */
        ActivationDetails *activation_details;

        /* Tweaking the GC logic */
        CollectMode collect_mode;

        /* The current invocation ID */
        sd_id128_t invocation_id;
        char invocation_id_string[SD_ID128_STRING_MAX]; /* useful when logging */

        /* Garbage collect us we nobody wants or requires us anymore */
        bool stop_when_unneeded;

        /* Create default dependencies */
        bool default_dependencies;

        /* Configure so that the unit survives a system transition without stopping/starting. */
        bool survive_final_kill_signal;

        /* Refuse manual starting, allow starting only indirectly via dependency. */
        bool refuse_manual_start;

        /* Don't allow the user to stop this unit manually, allow stopping only indirectly via dependency. */
        bool refuse_manual_stop;

        /* Allow isolation requests */
        bool allow_isolate;

        /* Ignore this unit when isolating */
        bool ignore_on_isolate;

        /* Did the last condition check succeed? */
        bool condition_result;
        bool assert_result;

        /* Is this a transient unit? */
        bool transient;

        /* Is this a unit that is always running and cannot be stopped? */
        bool perpetual;

        /* When true logs about this unit will be at debug level regardless of other log level settings */
        bool debug_invocation;

        /* Booleans indicating membership of this unit in the various queues */
        bool in_load_queue:1;
        bool in_dbus_queue:1;
        bool in_cleanup_queue:1;
        bool in_gc_queue:1;
        bool in_cgroup_realize_queue:1;
        bool in_cgroup_empty_queue:1;
        bool in_cgroup_oom_queue:1;
        bool in_target_deps_queue:1;
        bool in_stop_when_unneeded_queue:1;
        bool in_start_when_upheld_queue:1;
        bool in_stop_when_bound_queue:1;
        bool in_release_resources_queue:1;
        bool in_stop_notify_queue:1;

        bool sent_dbus_new_signal:1;

        bool job_running_timeout_set:1;

        bool in_audit:1;
        bool on_console:1;

        bool start_limit_hit:1;

        /* Did we already invoke unit_coldplug() for this unit? */
        bool coldplugged:1;

        /* For transient units: whether to add a bus track reference after creating the unit */
        bool bus_track_add:1;

        /* Remember which unit state files we created */
        bool exported_invocation_id:1;
        bool exported_log_level_max:1;
        bool exported_log_extra_fields:1;
        bool exported_log_ratelimit_interval:1;
        bool exported_log_ratelimit_burst:1;

        /* When writing transient unit files, stores which section we stored last. If < 0, we didn't write any yet. If
         * == 0 we are in the [Unit] section, if > 0 we are in the unit type-specific section. */
        signed int last_section_private:2;
} Unit;

typedef struct UnitStatusMessageFormats {
        const char *starting_stopping[2];
        const char *finished_start_job[_JOB_RESULT_MAX];
        const char *finished_stop_job[_JOB_RESULT_MAX];
        /* If this entry is present, it'll be called to provide a context-dependent format string,
         * or NULL to fall back to finished_{start,stop}_job; if those are NULL too, fall back to generic. */
        const char *(*finished_job)(Unit *u, JobType t, JobResult result);
} UnitStatusMessageFormats;

/* Flags used when writing drop-in files or transient unit files */
typedef enum UnitWriteFlags {
        /* Write a runtime unit file or drop-in (i.e. one below /run) */
        UNIT_RUNTIME                = 1 << 0,

        /* Write a persistent drop-in (i.e. one below /etc) */
        UNIT_PERSISTENT             = 1 << 1,

        /* Place this item in the per-unit-type private section, instead of [Unit] */
        UNIT_PRIVATE                = 1 << 2,

        /* Apply specifier escaping */
        UNIT_ESCAPE_SPECIFIERS      = 1 << 3,

        /* Escape elements of ExecStart= syntax, incl. prevention of variable expansion */
        UNIT_ESCAPE_EXEC_SYNTAX_ENV = 1 << 4,

        /* Escape elements of ExecStart=: syntax (no variable expansion) */
        UNIT_ESCAPE_EXEC_SYNTAX     = 1 << 5,

        /* Apply C escaping before writing */
        UNIT_ESCAPE_C               = 1 << 6,
} UnitWriteFlags;

/* Returns true if neither persistent, nor runtime storage is requested, i.e. this is a check invocation only */
static inline bool UNIT_WRITE_FLAGS_NOOP(UnitWriteFlags flags) {
        return (flags & (UNIT_RUNTIME|UNIT_PERSISTENT)) == 0;
}

#include "kill.h"

/* The static const, immutable data about a specific unit type */
typedef struct UnitVTable {
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

        /* If greater than 0, the offset into the object where the pointer to ExecRuntime is found, if
         * the unit type has that */
        size_t exec_runtime_offset;

        /* If greater than 0, the offset into the object where the pointer to CGroupRuntime is found, if the
         * unit type has that */
        size_t cgroup_runtime_offset;

        /* The name of the configuration file section with the private settings of this unit */
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

        /* During deserialization we only record the intended state to return to. With coldplug() we actually put the
         * deserialized state in effect. This is where unit_notify() should be called to start things up. Note that
         * this callback is invoked *before* we leave the reloading state of the manager, i.e. *before* we consider the
         * reloading to be complete. Thus, this callback should just restore the exact same state for any unit that was
         * in effect before the reload, i.e. units should not catch up with changes happened during the reload. That's
         * what catchup() below is for. */
        int (*coldplug)(Unit *u);

        /* This is called shortly after all units' coldplug() call was invoked, and *after* the manager left the
         * reloading state. It's supposed to catch up with state changes due to external events we missed so far (for
         * example because they took place while we were reloading/reexecing) */
        void (*catchup)(Unit *u);

        void (*dump)(Unit *u, FILE *f, const char *prefix);

        int (*start)(Unit *u);
        int (*stop)(Unit *u);
        int (*reload)(Unit *u);

        /* Clear out the various runtime/state/cache/logs/configuration data */
        int (*clean)(Unit *u, ExecCleanMask m);

        /* Freeze or thaw the unit. Returns > 0 to indicate that the request will be handled asynchronously; unit_frozen
         * or unit_thawed should be called once the operation is done. Returns 0 if done successfully, or < 0 on error. */
        int (*freezer_action)(Unit *u, FreezerAction a);
        bool (*can_freeze)(const Unit *u);

        /* Return which kind of data can be cleaned */
        int (*can_clean)(Unit *u, ExecCleanMask *ret);

        bool (*can_reload)(Unit *u);

        /* Add a bind/image mount into the unit namespace while it is running. */
        int (*live_mount)(Unit *u, const char *src, const char *dst, sd_bus_message *message, MountInNamespaceFlags flags, const MountOptions *options, sd_bus_error *reterr_error);
        int (*can_live_mount)(Unit *u, sd_bus_error *reterr_error);

        /* Serialize state and file descriptors that should be carried over into the new
         * instance after reexecution. */
        int (*serialize)(Unit *u, FILE *f, FDSet *fds);

        /* Restore one item from the serialization */
        int (*deserialize_item)(Unit *u, const char *key, const char *data, FDSet *fds);

        /* Try to match up fds with what we need for this unit */
        void (*distribute_fds)(Unit *u, FDSet *fds);

        /* Boils down the more complex internal state of this unit to
         * a simpler one that the engine can understand */
        UnitActiveState (*active_state)(Unit *u);

        /* Returns the substate specific to this unit type as
         * string. This is purely information so that we can give the
         * user a more fine grained explanation in which actual state a
         * unit is in. */
        const char* (*sub_state_to_string)(Unit *u);

        /* Additionally to UnitActiveState determine whether unit is to be restarted. */
        bool (*will_restart)(Unit *u);

        /* Return false when there is a reason to prevent this unit from being gc'ed
         * even though nothing references it and it isn't active in any way. */
        bool (*may_gc)(Unit *u);

        /* Return true when the unit is not controlled by the manager (e.g. extrinsic mounts). */
        bool (*is_extrinsic)(Unit *u);

        /* When the unit is not running and no job for it queued we shall release its runtime resources */
        void (*release_resources)(Unit *u);

        /* Invoked on every child that died */
        void (*sigchld_event)(Unit *u, pid_t pid, int code, int status);

        /* Reset failed state if we are in failed state */
        void (*reset_failed)(Unit *u);

        /* Called whenever any of the cgroups this unit watches for ran empty */
        void (*notify_cgroup_empty)(Unit *u);

        /* Called whenever an OOM kill event on this unit was seen */
        void (*notify_cgroup_oom)(Unit *u, bool managed_oom);

        /* Called whenever a process of this unit sends us a message */
        void (*notify_message)(Unit *u, PidRef *pidref, const struct ucred *ucred, char * const *tags, FDSet *fds);

        /* Called whenever we learn a handoff timestamp */
        void (*notify_handoff_timestamp)(Unit *u, const struct ucred *ucred, const dual_timestamp *ts);

        /* Called whenever we learn about a child process */
        void (*notify_pidref)(Unit *u, PidRef *parent_pidref, PidRef *child_pidref);

        /* Called whenever a name this Unit registered for comes or goes away. */
        void (*bus_name_owner_change)(Unit *u, const char *new_owner);

        /* Called for each property that is being set */
        int (*bus_set_property)(Unit *u, const char *name, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *reterr_error);

        /* Called after at least one property got changed to apply the necessary change */
        int (*bus_commit_properties)(Unit *u);

        /* Return the unit this unit is following */
        Unit* (*following)(Unit *u);

        /* Return the set of units that are following each other */
        int (*following_set)(Unit *u, Set **s);

        /* Invoked each time a unit this unit is triggering changes
         * state or gains/loses a job */
        void (*trigger_notify)(Unit *u, Unit *trigger);

        /* Invoked when some other units stop */
        bool (*stop_notify)(Unit *u);

        /* Called whenever CLOCK_REALTIME made a jump */
        void (*time_change)(Unit *u);

        /* Called whenever /etc/localtime was modified */
        void (*timezone_change)(Unit *u);

        /* Returns the next timeout of a unit */
        int (*get_timeout)(Unit *u, usec_t *timeout);

        /* Returns the start timeout of a unit */
        usec_t (*get_timeout_start_usec)(Unit *u);

        /* Returns the main PID if there is any defined, or NULL. */
        PidRef* (*main_pid)(Unit *u, bool *ret_is_alien);

        /* Returns the control PID if there is any defined, or NULL. */
        PidRef* (*control_pid)(Unit *u);

        /* Returns true if the unit currently needs access to the console */
        bool (*needs_console)(Unit *u);

        /* Returns the exit status to propagate in case of FailureAction=exit/SuccessAction=exit; usually returns the
         * exit code of the "main" process of the service or similar. */
        int (*exit_status)(Unit *u);

        /* Return a copy of the status string pointer. */
        const char* (*status_text)(Unit *u);

        /* Like the enumerate() callback further down, but only enumerates the perpetual units, i.e. all units that
         * unconditionally exist and are always active. The main reason to keep both enumeration functions separate is
         * philosophical: the state of perpetual units should be put in place by coldplug(), while the state of those
         * discovered through regular enumeration should be put in place by catchup(), see below. */
        void (*enumerate_perpetual)(Manager *m);

        /* This is called for each unit type and should be used to enumerate units already existing in the system
         * internally and load them. However, everything that is loaded here should still stay in inactive state. It is
         * the job of the catchup() call above to put the units into the discovered state. */
        void (*enumerate)(Manager *m);

        /* Type specific cleanups. */
        void (*shutdown)(Manager *m);

        /* If this function is set and returns false all jobs for units
         * of this type will immediately fail. */
        bool (*supported)(void);

        /* If this function is set, it's invoked first as part of starting a unit to allow start rate
         * limiting checks and unit state checks to occur before we do anything else. */
        int (*test_startable)(Unit *u);

        /* Returns > 0 if the whole subsystem is ratelimited, and new start operations should not be started
         * for this unit type right now. */
        int (*subsystem_ratelimited)(Manager *m);

        /* The strings to print in status messages */
        UnitStatusMessageFormats status_message_formats;

        /* True if transient units of this type are OK */
        bool can_transient;

        /* True if cgroup delegation is permissible */
        bool can_delegate;

        /* True if the unit type triggers other units, i.e. can have a UNIT_TRIGGERS dependency */
        bool can_trigger;

        /* True if the unit type knows a failure state, and thus can be source of an OnFailure= dependency */
        bool can_fail;

        /* True if units of this type shall be startable only once and then never again */
        bool once_only;

        /* Do not serialize this unit when preparing for root switch */
        bool exclude_from_switch_root_serialization;

        /* True if queued jobs of this type should be GC'ed if no other job needs them anymore */
        bool gc_jobs;

        /* True if systemd-oomd can monitor and act on this unit's recursive children's cgroups  */
        bool can_set_managed_oom;

        /* If true, we'll notify plymouth about this unit */
        bool notify_plymouth;

        /* If true, we'll notify a surrounding VMM/container manager about this unit becoming available */
        bool notify_supervisor;

        /* The audit events to generate on start + stop (or 0 if none shall be generated) */
        int audit_start_message_type;
        int audit_stop_message_type;
} UnitVTable;

extern const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX];

static inline const UnitVTable* UNIT_VTABLE(const Unit *u) {
        return unit_vtable[u->type];
}

/* For casting a unit into the various unit types */
#define DEFINE_CAST(UPPERCASE, MixedCase)                               \
        static inline MixedCase* UPPERCASE(Unit *u) {                   \
                if (_unlikely_(!u || u->type != UNIT_##UPPERCASE))      \
                        return NULL;                                    \
                                                                        \
                return (MixedCase*) u;                                  \
        }

/* For casting the various unit types into a unit */
#define UNIT(u)                                         \
        ({                                              \
                typeof(u) _u_ = (u);                    \
                Unit *_w_ = _u_ ? &(_u_)->meta : NULL;  \
                _w_;                                    \
        })

#define UNIT_HAS_EXEC_CONTEXT(u) (UNIT_VTABLE(u)->exec_context_offset > 0)
#define UNIT_HAS_CGROUP_CONTEXT(u) (UNIT_VTABLE(u)->cgroup_context_offset > 0)
#define UNIT_HAS_KILL_CONTEXT(u) (UNIT_VTABLE(u)->kill_context_offset > 0)

Unit* unit_has_dependency(const Unit *u, UnitDependencyAtom atom, Unit *other);
int unit_get_dependency_array(const Unit *u, UnitDependencyAtom atom, Unit ***ret_array);
int unit_get_transitive_dependency_set(Unit *u, UnitDependencyAtom atom, Set **ret);

static inline Hashmap* unit_get_dependencies(Unit *u, UnitDependency d) {
        return hashmap_get(u->dependencies, UNIT_DEPENDENCY_TO_PTR(d));
}

static inline Unit* UNIT_TRIGGER(Unit *u) {
        return unit_has_dependency(u, UNIT_ATOM_TRIGGERS, NULL);
}

static inline Unit* UNIT_GET_SLICE(const Unit *u) {
        return unit_has_dependency(u, UNIT_ATOM_IN_SLICE, NULL);
}

Unit* unit_new(Manager *m, size_t size);
Unit* unit_free(Unit *u);
DEFINE_TRIVIAL_CLEANUP_FUNC(Unit *, unit_free);

int unit_new_for_name(Manager *m, size_t size, const char *name, Unit **ret);
int unit_add_name(Unit *u, const char *text);

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other, bool add_reference, UnitDependencyMask mask);
int unit_add_two_dependencies(Unit *u, UnitDependency d, UnitDependency e, Unit *other, bool add_reference, UnitDependencyMask mask);

int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name, bool add_reference, UnitDependencyMask mask);
int unit_add_two_dependencies_by_name(Unit *u, UnitDependency d, UnitDependency e, const char *name, bool add_reference, UnitDependencyMask mask);

int unit_add_exec_dependencies(Unit *u, ExecContext *c);

int unit_choose_id(Unit *u, const char *name);
int unit_set_description(Unit *u, const char *description);

void unit_release_resources(Unit *u);

bool unit_may_gc(Unit *u);

static inline bool unit_is_extrinsic(Unit *u) {
        return u->perpetual ||
                (UNIT_VTABLE(u)->is_extrinsic && UNIT_VTABLE(u)->is_extrinsic(u));
}

static inline const char* unit_status_text(Unit *u) {
        if (u && UNIT_VTABLE(u)->status_text)
                return UNIT_VTABLE(u)->status_text(u);
        return NULL;
}

void unit_add_to_load_queue(Unit *u);
void unit_add_to_dbus_queue(Unit *u);
void unit_add_to_cleanup_queue(Unit *u);
void unit_add_to_gc_queue(Unit *u);
void unit_add_to_target_deps_queue(Unit *u);
void unit_submit_to_stop_when_unneeded_queue(Unit *u);
void unit_submit_to_start_when_upheld_queue(Unit *u);
void unit_submit_to_stop_when_bound_queue(Unit *u);
void unit_submit_to_release_resources_queue(Unit *u);
void unit_add_to_stop_notify_queue(Unit *u);
void unit_remove_from_stop_notify_queue(Unit *u);

int unit_merge(Unit *u, Unit *other);
int unit_merge_by_name(Unit *u, const char *name);

Unit *unit_follow_merge(Unit *u) _pure_;

int unit_load_fragment_and_dropin(Unit *u, bool fragment_required);
int unit_load(Unit *unit);

int unit_set_slice(Unit *u, Unit *slice);
int unit_set_default_slice(Unit *u);

const char* unit_description(Unit *u) _pure_;
const char* unit_status_string(Unit *u, char **ret_combined_buffer);

bool unit_has_name(const Unit *u, const char *name);

UnitActiveState unit_active_state(Unit *u);

const char* unit_sub_state_to_string(Unit *u);

bool unit_can_reload(Unit *u) _pure_;
bool unit_can_start(Unit *u) _pure_;
bool unit_can_stop(Unit *u) _pure_;
bool unit_can_isolate(Unit *u) _pure_;

int unit_start(Unit *u, ActivationDetails *details);
int unit_stop(Unit *u);
int unit_reload(Unit *u);

int unit_kill(Unit *u, KillWhom w, const char *subgroup, int signo, int code, int value, sd_bus_error *ret_error);

void unit_notify_cgroup_oom(Unit *u, bool managed_oom);

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns, bool reload_success);

int unit_watch_pidref(Unit *u, const PidRef *pid, bool exclusive);
void unit_unwatch_pidref(Unit *u, const PidRef *pid);
void unit_unwatch_all_pids(Unit *u);
void unit_unwatch_pidref_done(Unit *u, PidRef *pidref);

int unit_install_bus_match(Unit *u, sd_bus *bus, const char *name);
int unit_watch_bus_name(Unit *u, const char *name);
void unit_unwatch_bus_name(Unit *u, const char *name);

bool unit_job_is_applicable(Unit *u, JobType j);

int setenv_unit_path(const char *p);

char* unit_dbus_path(Unit *u);
char* unit_dbus_path_invocation_id(Unit *u);

int unit_load_related_unit(Unit *u, const char *type, Unit **_found);

int unit_add_node_dependency(Unit *u, const char *what, UnitDependency d, UnitDependencyMask mask);
int unit_add_blockdev_dependency(Unit *u, const char *what, UnitDependencyMask mask);

int unit_coldplug(Unit *u);
void unit_catchup(Unit *u);

void unit_status_printf(Unit *u, StatusType status_type, const char *status, const char *format, const char *ident) _printf_(4, 0);

bool unit_need_daemon_reload(Unit *u);

void unit_reset_failed(Unit *u);

Unit *unit_following(Unit *u);
int unit_following_set(Unit *u, Set **s);

const char* unit_slice_name(Unit *u);

bool unit_stop_pending(Unit *u) _pure_;
bool unit_inactive_or_pending(Unit *u) _pure_;
bool unit_active_or_pending(Unit *u);
bool unit_will_restart_default(Unit *u);
bool unit_will_restart(Unit *u);

int unit_add_default_target_dependency(Unit *u, Unit *target);

void unit_start_on_termination_deps(Unit *u, UnitDependencyAtom atom);
void unit_trigger_notify(Unit *u);

int unit_get_exec_quota_stats(Unit *u, ExecContext *c, ExecDirectoryType dt, uint64_t *ret_usage, uint64_t *ret_limit);

UnitFileState unit_get_unit_file_state(Unit *u);
PresetAction unit_get_unit_file_preset(Unit *u);

Unit* unit_ref_set(UnitRef *ref, Unit *source, Unit *target);
void unit_ref_unset(UnitRef *ref);

#define UNIT_DEREF(ref) ((ref).target)
#define UNIT_ISSET(ref) (!!(ref).target)

int unit_patch_contexts(Unit *u);

ExecContext* unit_get_exec_context(const Unit *u) _pure_;
KillContext* unit_get_kill_context(const Unit *u) _pure_;
CGroupContext* unit_get_cgroup_context(const Unit *u) _pure_;

ExecRuntime* unit_get_exec_runtime(const Unit *u) _pure_;
CGroupRuntime* unit_get_cgroup_runtime(const Unit *u) _pure_;

int unit_setup_exec_runtime(Unit *u);
CGroupRuntime* unit_setup_cgroup_runtime(Unit *u);

const char* unit_escape_setting(const char *s, UnitWriteFlags flags, char **buf);
char* unit_concat_strv(char **l, UnitWriteFlags flags);

int unit_write_setting(Unit *u, UnitWriteFlags flags, const char *name, const char *data);
int unit_write_settingf(Unit *u, UnitWriteFlags flags, const char *name, const char *format, ...) _printf_(4,5);

int unit_kill_context(Unit *u, KillOperation k);

int unit_make_transient(Unit *u);

int unit_add_mounts_for(Unit *u, const char *path, UnitDependencyMask mask, UnitMountDependencyType type);

bool unit_type_supported(UnitType t);

bool unit_is_pristine(Unit *u);

bool unit_is_unneeded(Unit *u);
bool unit_is_upheld_by_active(Unit *u, Unit **ret_culprit);
bool unit_is_bound_by_inactive(Unit *u, Unit **ret_culprit);

PidRef* unit_control_pid(Unit *u);
PidRef* unit_main_pid_full(Unit *u, bool *ret_is_alien);
static inline PidRef* unit_main_pid(Unit *u) {
        return unit_main_pid_full(u, NULL);
}

void unit_warn_if_dir_nonempty(Unit *u, const char* where);
int unit_log_noncanonical_mount_path(Unit *u, const char *where);
int unit_fail_if_noncanonical_mount_path(Unit *u, const char* where);

int unit_test_start_limit(Unit *u);

int unit_ref_uid_gid(Unit *u, uid_t uid, gid_t gid);
void unit_unref_uid_gid(Unit *u, bool destroy_now);

void unit_notify_user_lookup(Unit *u, uid_t uid, gid_t gid);

int unit_set_invocation_id(Unit *u, sd_id128_t id);
int unit_acquire_invocation_id(Unit *u);

int unit_set_exec_params(Unit *u, ExecParameters *p);

int unit_fork_helper_process_full(Unit *u, const char *name, bool into_cgroup, ForkFlags flags, PidRef *ret);
int unit_fork_helper_process(Unit *u, const char *name, bool into_cgroup, PidRef *ret);
int unit_fork_and_watch_rm_rf(Unit *u, char **paths, PidRef *ret);

void unit_remove_dependencies(Unit *u, UnitDependencyMask mask);

void unit_export_state_files(Unit *u);
void unit_unlink_state_files(Unit *u);

int unit_set_debug_invocation(Unit *u, bool enable);

int unit_prepare_exec(Unit *u);

int unit_warn_leftover_processes(Unit *u, bool start);

bool unit_needs_console(Unit *u);

int unit_pid_attachable(Unit *unit, PidRef *pid, sd_bus_error *reterr_error);

static inline bool unit_has_job_type(Unit *u, JobType type) {
        return u && u->job && u->job->type == type;
}

int unit_get_log_level_max(const Unit *u);

bool unit_log_level_test(const Unit *u, int level);

/* unit_log_skip is for cases like ExecCondition= where a unit is considered "done"
 * after some execution, rather than succeeded or failed. */
void unit_log_skip(Unit *u, const char *result);
void unit_log_success(Unit *u);
void unit_log_failure(Unit *u, const char *result);
static inline void unit_log_result(Unit *u, bool success, const char *result) {
        if (success)
                unit_log_success(u);
        else
                unit_log_failure(u, result);
}

void unit_log_process_exit(Unit *u, const char *kind, const char *command, bool success, int code, int status);

int unit_exit_status(Unit *u);
int unit_success_action_exit_status(Unit *u);
int unit_failure_action_exit_status(Unit *u);

int unit_test_trigger_loaded(Unit *u);

void unit_destroy_runtime_data(Unit *u, const ExecContext *context, bool destroy_runtime_dir);
int unit_clean(Unit *u, ExecCleanMask mask);
int unit_can_clean(Unit *u, ExecCleanMask *ret_mask);

bool unit_can_start_refuse_manual(Unit *u);
bool unit_can_stop_refuse_manual(Unit *u);
bool unit_can_isolate_refuse_manual(Unit *u);

bool unit_can_freeze(const Unit *u);
int unit_freezer_action(Unit *u, FreezerAction action);
void unit_next_freezer_state(Unit *u, FreezerAction action, FreezerState *ret_next, FreezerState *ret_objective);
void unit_set_freezer_state(Unit *u, FreezerState state);
void unit_freezer_complete(Unit *u, FreezerState kernel_state);

int unit_can_live_mount(Unit *u, sd_bus_error *reterr_error);
int unit_live_mount(
                Unit *u,
                const char *src,
                const char *dst,
                sd_bus_message *message,
                MountInNamespaceFlags flags,
                const MountOptions *options,
                sd_bus_error *reterr_error);

Condition *unit_find_failed_condition(Unit *u);

int unit_arm_timer(Unit *u, sd_event_source **source, bool relative, usec_t usec, sd_event_time_handler_t handler);

bool unit_passes_filter(Unit *u, char * const *states, char * const *patterns);

int unit_compare_priority(Unit *a, Unit *b);

const char* unit_log_field(const Unit *u);
const char* unit_invocation_log_field(const Unit *u);

DECLARE_STRING_TABLE_LOOKUP(unit_mount_dependency_type, UnitMountDependencyType);
UnitDependency unit_mount_dependency_type_to_dependency_type(UnitMountDependencyType t) _pure_;

DECLARE_STRING_TABLE_LOOKUP(oom_policy, OOMPolicy);

int unit_queue_job_check_and_mangle_type(Unit *u, JobType *type, bool reload_if_possible, sd_bus_error *reterr_error);

int parse_unit_marker(const char *marker, unsigned *settings, unsigned *mask);

/* Macros which append UNIT= or USER_UNIT= to the message */

#define log_unit_full_errno_zerook(unit, level, error, ...)             \
        ({                                                              \
                const Unit *_u = (unit);                                \
                const int _l = (level);                                 \
                LOG_CONTEXT_SET_LOG_LEVEL(unit_get_log_level_max(_u));  \
                const ExecContext *_c = _u ? unit_get_exec_context(_u) : NULL; \
                LOG_CONTEXT_PUSH_IOV(_c ? _c->log_extra_fields : NULL,  \
                                     _c ? _c->n_log_extra_fields : 0);  \
                _u ? log_object_internal(_l, error, PROJECT_FILE, __LINE__, __func__,  unit_log_field(_u), _u->id, unit_invocation_log_field(_u), _u->invocation_id_string, ##__VA_ARGS__) : \
                     log_internal(_l, error, PROJECT_FILE, __LINE__, __func__, ##__VA_ARGS__); \
        })

#define log_unit_full_errno(unit, level, error, ...) \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_unit_full_errno_zerook(unit, level, _error, ##__VA_ARGS__); \
        })

#define log_unit_full(unit, level, ...) (void) log_unit_full_errno_zerook(unit, level, 0, __VA_ARGS__)

#define log_unit_debug(unit, ...)   log_unit_full(unit, LOG_DEBUG, __VA_ARGS__)
#define log_unit_info(unit, ...)    log_unit_full(unit, LOG_INFO, __VA_ARGS__)
#define log_unit_notice(unit, ...)  log_unit_full(unit, LOG_NOTICE, __VA_ARGS__)
#define log_unit_warning(unit, ...) log_unit_full(unit, LOG_WARNING, __VA_ARGS__)
#define log_unit_error(unit, ...)   log_unit_full(unit, LOG_ERR, __VA_ARGS__)

#define log_unit_debug_errno(unit, error, ...)   log_unit_full_errno(unit, LOG_DEBUG, error, __VA_ARGS__)
#define log_unit_info_errno(unit, error, ...)    log_unit_full_errno(unit, LOG_INFO, error, __VA_ARGS__)
#define log_unit_notice_errno(unit, error, ...)  log_unit_full_errno(unit, LOG_NOTICE, error, __VA_ARGS__)
#define log_unit_warning_errno(unit, error, ...) log_unit_full_errno(unit, LOG_WARNING, error, __VA_ARGS__)
#define log_unit_error_errno(unit, error, ...)   log_unit_full_errno(unit, LOG_ERR, error, __VA_ARGS__)

#if LOG_TRACE
#  define log_unit_trace(...)          log_unit_debug(__VA_ARGS__)
#  define log_unit_trace_errno(...)    log_unit_debug_errno(__VA_ARGS__)
#else
#  define log_unit_trace(...)          do {} while (0)
#  define log_unit_trace_errno(e, ...) (-ERRNO_VALUE(e))
#endif

#define log_unit_struct_errno(unit, level, error, ...)                  \
        ({                                                              \
                const Unit *_u = (unit);                                \
                const int _l = (level);                                 \
                LOG_CONTEXT_SET_LOG_LEVEL(unit_get_log_level_max(_u));  \
                const ExecContext *_c = _u ? unit_get_exec_context(_u) : NULL; \
                LOG_CONTEXT_PUSH_IOV(_c ? _c->log_extra_fields : NULL,  \
                                     _c ? _c->n_log_extra_fields : 0);  \
                log_struct_errno(_l, error, __VA_ARGS__, LOG_UNIT_ID(_u)); \
        })

#define log_unit_struct(unit, level, ...) log_unit_struct_errno(unit, level, 0, __VA_ARGS__)

#define log_unit_struct_iovec_errno(unit, level, error, iovec, n_iovec) \
        ({                                                              \
                const Unit *_u = (unit);                                \
                const int _l = (level);                                 \
                LOG_CONTEXT_SET_LOG_LEVEL(unit_get_log_level_max(_u));  \
                const ExecContext *_c = _u ? unit_get_exec_context(_u) : NULL; \
                LOG_CONTEXT_PUSH_IOV(_c ? _c->log_extra_fields : NULL,  \
                                     _c ? _c->n_log_extra_fields : 0);  \
                log_struct_iovec_errno(_l, error, iovec, n_iovec);      \
        })

#define log_unit_struct_iovec(unit, level, iovec, n_iovec) log_unit_struct_iovec_errno(unit, level, 0, iovec, n_iovec)

/* Like LOG_MESSAGE(), but with the unit name prefixed. */
#define LOG_UNIT_MESSAGE(unit, fmt, ...) LOG_MESSAGE("%s: " fmt, (unit)->id, ##__VA_ARGS__)
#define LOG_UNIT_ID(unit) LOG_ITEM("%s%s", unit_log_field((unit)), (unit)->id)
#define LOG_UNIT_INVOCATION_ID(unit) LOG_ITEM("%s%s", unit_invocation_log_field((unit)), (unit)->invocation_id_string)

DECLARE_STRING_TABLE_LOOKUP(collect_mode, CollectMode);

typedef struct UnitForEachDependencyData {
        /* Stores state for the FOREACH macro below for iterating through all deps that have any of the
         * specified dependency atom bits set */
        const Unit *unit;
        UnitDependencyAtom match_atom;
        Hashmap *by_type, *by_unit;
        void *current_type;
        Iterator by_type_iterator, by_unit_iterator;
        Unit **current_unit;
        uint64_t generation;
        unsigned n_restart;
        bool restart_on_generation_change;
} UnitForEachDependencyData;

/* Let's not restart the loop infinitely. */
#define MAX_FOREACH_DEPENDENCY_RESTART 100000

/* Iterates through all dependencies that have a specific atom in the dependency type set. This tries to be
 * smart: if the atom is unique, we'll directly go to right entry. Otherwise we'll iterate through the
 * per-dependency type hashmap and match all dep that have the right atom set. */
#define _UNIT_FOREACH_DEPENDENCY(other, u, ma, restart, data)           \
        for (UnitForEachDependencyData data = {                         \
                        .unit = (u),                                    \
                        .match_atom = (ma),                             \
                        .current_unit = &(other),                       \
                        .restart_on_generation_change = (restart),      \
                };                                                      \
             ({                                                         \
                     UnitDependency _dt = _UNIT_DEPENDENCY_INVALID;     \
                     bool _found;                                       \
                                                                        \
                     if (data.generation == 0 ||                        \
                         (data.restart_on_generation_change &&          \
                          data.generation != data.unit->dependency_generation)) { \
                             data.generation = data.unit->dependency_generation; \
                             data.by_type = data.unit->dependencies;    \
                             data.by_type_iterator = ITERATOR_FIRST;    \
                             assert_se(data.n_restart++ < MAX_FOREACH_DEPENDENCY_RESTART); \
                     } else                                             \
                             assert(data.generation == data.unit->dependency_generation); \
                                                                        \
                     if (data.by_type && ITERATOR_IS_FIRST(data.by_type_iterator)) { \
                             _dt = unit_dependency_from_unique_atom(data.match_atom); \
                             if (_dt >= 0) {                            \
                                     data.by_unit = hashmap_get(data.by_type, UNIT_DEPENDENCY_TO_PTR(_dt)); \
                                     data.current_type = UNIT_DEPENDENCY_TO_PTR(_dt); \
                                     data.by_type = NULL;               \
                                     _found = !!data.by_unit;           \
                             }                                          \
                     }                                                  \
                     if (_dt < 0)                                       \
                             _found = hashmap_iterate(data.by_type,     \
                                                      &data.by_type_iterator, \
                                                      (void**) &(data.by_unit), \
                                                      (const void**) &(data.current_type)); \
                     _found;                                            \
             }); )                                                      \
                if ((unit_dependency_to_atom(UNIT_DEPENDENCY_FROM_PTR(data.current_type)) & data.match_atom) != 0) \
                        for (data.by_unit_iterator = ITERATOR_FIRST;    \
                             data.generation == data.unit->dependency_generation && \
                                hashmap_iterate(data.by_unit,           \
                                                &data.by_unit_iterator, \
                                                NULL,                   \
                                                (const void**) data.current_unit); )

/* Note: this matches deps that have *any* of the atoms specified in match_atom set */
#define UNIT_FOREACH_DEPENDENCY(other, u, match_atom) \
        _UNIT_FOREACH_DEPENDENCY(other, u, match_atom, false, UNIQ_T(data, UNIQ))
#define UNIT_FOREACH_DEPENDENCY_SAFE(other, u, match_atom) \
        _UNIT_FOREACH_DEPENDENCY(other, u, match_atom, true, UNIQ_T(data, UNIQ))

#define _LOG_CONTEXT_PUSH_UNIT(unit, u, c)                                                              \
        const Unit *u = (unit);                                                                         \
        const ExecContext *c = unit_get_exec_context(u);                                                \
        LOG_CONTEXT_PUSH_KEY_VALUE(unit_log_field(u), u->id);                                           \
        LOG_CONTEXT_PUSH_KEY_VALUE(unit_invocation_log_field(u), u->invocation_id_string);              \
        LOG_CONTEXT_PUSH_IOV(c ? c->log_extra_fields : NULL, c ? c->n_log_extra_fields : 0);            \
        LOG_CONTEXT_SET_LOG_LEVEL(unit_get_log_level_max(u))

#define LOG_CONTEXT_PUSH_UNIT(unit) \
        _LOG_CONTEXT_PUSH_UNIT(unit, UNIQ_T(u, UNIQ), UNIQ_T(c, UNIQ))
