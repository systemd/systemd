/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"

#include "common-signal.h"
#include "cgroup-util.h"
#include "cgroup.h"
#include "fdset.h"
#include "hashmap.h"
#include "list.h"
#include "prioq.h"
#include "ratelimit.h"
#include "varlink.h"

struct libmnt_monitor;
typedef struct Unit Unit;

/* Enforce upper limit how many names we allow */
#define MANAGER_MAX_NAMES 131072 /* 128K */

/* On sigrtmin+18, private commands */
enum {
        MANAGER_SIGNAL_COMMAND_DUMP_JOBS = _COMMON_SIGNAL_COMMAND_PRIVATE_BASE + 0,
        _MANAGER_SIGNAL_COMMAND_MAX,
};

assert_cc((int) _MANAGER_SIGNAL_COMMAND_MAX <= (int) _COMMON_SIGNAL_COMMAND_PRIVATE_END);

typedef struct Manager Manager;

/* An externally visible state. We don't actually maintain this as state variable, but derive it from various fields
 * when requested */
typedef enum ManagerState {
        MANAGER_INITIALIZING,
        MANAGER_STARTING,
        MANAGER_RUNNING,
        MANAGER_DEGRADED,
        MANAGER_MAINTENANCE,
        MANAGER_STOPPING,
        _MANAGER_STATE_MAX,
        _MANAGER_STATE_INVALID = -EINVAL,
} ManagerState;

typedef enum ManagerObjective {
        MANAGER_OK,
        MANAGER_EXIT,
        MANAGER_RELOAD,
        MANAGER_REEXECUTE,
        MANAGER_REBOOT,
        MANAGER_SOFT_REBOOT,
        MANAGER_POWEROFF,
        MANAGER_HALT,
        MANAGER_KEXEC,
        MANAGER_SWITCH_ROOT,
        _MANAGER_OBJECTIVE_MAX,
        _MANAGER_OBJECTIVE_INVALID = -EINVAL,
} ManagerObjective;

typedef enum StatusType {
        STATUS_TYPE_EPHEMERAL,
        STATUS_TYPE_NORMAL,
        STATUS_TYPE_NOTICE,
        STATUS_TYPE_EMERGENCY,
} StatusType;

typedef enum OOMPolicy {
        OOM_CONTINUE,          /* The kernel or systemd-oomd kills the process it wants to kill, and that's it */
        OOM_STOP,              /* The kernel or systemd-oomd kills the process it wants to kill, and we stop the unit */
        OOM_KILL,              /* The kernel or systemd-oomd kills the process it wants to kill, and all others in the unit, and we stop the unit */
        _OOM_POLICY_MAX,
        _OOM_POLICY_INVALID = -EINVAL,
} OOMPolicy;

/* Notes:
 * 1. TIMESTAMP_FIRMWARE, TIMESTAMP_LOADER, TIMESTAMP_KERNEL, TIMESTAMP_INITRD,
 *    TIMESTAMP_SECURITY_START, and TIMESTAMP_SECURITY_FINISH are set only when
 *    the manager is system and not running under container environment.
 *
 * 2. The monotonic timestamp of TIMESTAMP_KERNEL is always zero.
 *
 * 3. The realtime timestamp of TIMESTAMP_KERNEL will be unset if the system does not
 *    have RTC.
 *
 * 4. TIMESTAMP_FIRMWARE and TIMESTAMP_LOADER will be unset if the system does not
 *    have RTC, or systemd is built without EFI support.
 *
 * 5. The monotonic timestamps of TIMESTAMP_FIRMWARE and TIMESTAMP_LOADER are stored as
 *    negative of the actual value.
 *
 * 6. TIMESTAMP_USERSPACE is the timestamp of when the manager was started.
 *
 * 7. TIMESTAMP_INITRD_* are set only when the system is booted with an initrd.
 */

typedef enum ManagerTimestamp {
        MANAGER_TIMESTAMP_FIRMWARE,
        MANAGER_TIMESTAMP_LOADER,
        MANAGER_TIMESTAMP_KERNEL,
        MANAGER_TIMESTAMP_INITRD,
        MANAGER_TIMESTAMP_USERSPACE,
        MANAGER_TIMESTAMP_FINISH,

        MANAGER_TIMESTAMP_SECURITY_START,
        MANAGER_TIMESTAMP_SECURITY_FINISH,
        MANAGER_TIMESTAMP_GENERATORS_START,
        MANAGER_TIMESTAMP_GENERATORS_FINISH,
        MANAGER_TIMESTAMP_UNITS_LOAD_START,
        MANAGER_TIMESTAMP_UNITS_LOAD_FINISH,
        MANAGER_TIMESTAMP_UNITS_LOAD,

        MANAGER_TIMESTAMP_INITRD_SECURITY_START,
        MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH,
        MANAGER_TIMESTAMP_INITRD_GENERATORS_START,
        MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH,
        MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START,
        MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH,
        _MANAGER_TIMESTAMP_MAX,
        _MANAGER_TIMESTAMP_INVALID = -EINVAL,
} ManagerTimestamp;

typedef enum WatchdogType {
        WATCHDOG_RUNTIME,
        WATCHDOG_REBOOT,
        WATCHDOG_KEXEC,
        WATCHDOG_PRETIMEOUT,
        _WATCHDOG_TYPE_MAX,
} WatchdogType;

#include "execute.h"
#include "job.h"
#include "path-lookup.h"
#include "show-status.h"
#include "unit-name.h"
#include "unit.h"

typedef enum ManagerTestRunFlags {
        MANAGER_TEST_NORMAL                  = 0,       /* run normally */
        MANAGER_TEST_RUN_MINIMAL             = 1 << 0,  /* create basic data structures */
        MANAGER_TEST_RUN_BASIC               = 1 << 1,  /* interact with the environment */
        MANAGER_TEST_RUN_ENV_GENERATORS      = 1 << 2,  /* also run env generators  */
        MANAGER_TEST_RUN_GENERATORS          = 1 << 3,  /* also run unit generators */
        MANAGER_TEST_RUN_IGNORE_DEPENDENCIES = 1 << 4,  /* run while ignoring dependencies */
        MANAGER_TEST_DONT_OPEN_EXECUTOR      = 1 << 5,  /* avoid trying to load sd-executor */
        MANAGER_TEST_FULL = MANAGER_TEST_RUN_BASIC | MANAGER_TEST_RUN_ENV_GENERATORS | MANAGER_TEST_RUN_GENERATORS,
} ManagerTestRunFlags;

assert_cc((MANAGER_TEST_FULL & UINT8_MAX) == MANAGER_TEST_FULL);

/* Various defaults for unit file settings. */
typedef struct UnitDefaults {
        ExecOutput std_output, std_error;

        usec_t restart_usec, timeout_start_usec, timeout_stop_usec, timeout_abort_usec, device_timeout_usec;
        bool timeout_abort_set;

        usec_t start_limit_interval;
        unsigned start_limit_burst;

        bool cpu_accounting;
        bool memory_accounting;
        bool io_accounting;
        bool blockio_accounting;
        bool tasks_accounting;
        bool ip_accounting;

        CGroupTasksMax tasks_max;
        usec_t timer_accuracy_usec;

        OOMPolicy oom_policy;
        int oom_score_adjust;
        bool oom_score_adjust_set;

        CGroupPressureWatch memory_pressure_watch;
        usec_t memory_pressure_threshold_usec;

        char *smack_process_label;

        struct rlimit *rlimit[_RLIMIT_MAX];
} UnitDefaults;

struct Manager {
        /* Note that the set of units we know of is allowed to be
         * inconsistent. However the subset of it that is loaded may
         * not, and the list of jobs may neither. */

        /* Active jobs and units */
        Hashmap *units;  /* name string => Unit object n:1 */
        Hashmap *units_by_invocation_id;
        Hashmap *jobs;   /* job id => Job object 1:1 */

        /* To make it easy to iterate through the units of a specific
         * type we maintain a per type linked list */
        LIST_HEAD(Unit, units_by_type[_UNIT_TYPE_MAX]);

        /* Units that need to be loaded */
        LIST_HEAD(Unit, load_queue); /* this is actually more a stack than a queue, but uh. */

        /* Jobs that need to be run */
        struct Prioq *run_queue;

        /* Units and jobs that have not yet been announced via
         * D-Bus. When something about a job changes it is added here
         * if it is not in there yet. This allows easy coalescing of
         * D-Bus change signals. */
        LIST_HEAD(Unit, dbus_unit_queue);
        LIST_HEAD(Job, dbus_job_queue);

        /* Units to remove */
        LIST_HEAD(Unit, cleanup_queue);

        /* Units and jobs to check when doing GC */
        LIST_HEAD(Unit, gc_unit_queue);
        LIST_HEAD(Job, gc_job_queue);

        /* Units that should be realized */
        LIST_HEAD(Unit, cgroup_realize_queue);

        /* Units whose cgroup ran empty */
        LIST_HEAD(Unit, cgroup_empty_queue);

        /* Units whose memory.event fired */
        LIST_HEAD(Unit, cgroup_oom_queue);

        /* Target units whose default target dependencies haven't been set yet */
        LIST_HEAD(Unit, target_deps_queue);

        /* Units that might be subject to StopWhenUnneeded= clean-up */
        LIST_HEAD(Unit, stop_when_unneeded_queue);

        /* Units which are upheld by another other which we might need to act on */
        LIST_HEAD(Unit, start_when_upheld_queue);

        /* Units that have BindsTo= another unit, and might need to be shutdown because the bound unit is not active. */
        LIST_HEAD(Unit, stop_when_bound_queue);

        /* Units that have resources open, and where it might be good to check if they can be released now */
        LIST_HEAD(Unit, release_resources_queue);

        sd_event *event;

        /* This maps PIDs we care about to units that are interested in them. We allow multiple units to be
         * interested in the same PID and multiple PIDs to be relevant to the same unit. Since in most cases
         * only a single unit will be interested in the same PID though, we use a somewhat special structure
         * here: the first unit interested in a PID is stored in the hashmap 'watch_pids', keyed by the
         * PID. If there are other units interested too they'll be stored in a NULL-terminated array, stored
         * in the hashmap 'watch_pids_more', keyed by the PID. Thus to go through the full list of units
         * interested in a PID we must look into both hashmaps. */
        Hashmap *watch_pids;            /* PidRef* → Unit* */
        Hashmap *watch_pids_more;       /* PidRef* → NUL terminated array of Unit* */

        /* A set contains all units which cgroup should be refreshed after startup */
        Set *startup_units;

        /* A set which contains all currently failed units */
        Set *failed_units;

        sd_event_source *run_queue_event_source;

        char *notify_socket;
        int notify_fd;
        sd_event_source *notify_event_source;

        int cgroups_agent_fd;
        sd_event_source *cgroups_agent_event_source;

        int signal_fd;
        sd_event_source *signal_event_source;

        sd_event_source *sigchld_event_source;

        sd_event_source *time_change_event_source;

        sd_event_source *timezone_change_event_source;

        sd_event_source *jobs_in_progress_event_source;

        int user_lookup_fds[2];
        sd_event_source *user_lookup_event_source;

        RuntimeScope runtime_scope;

        LookupPaths lookup_paths;
        Hashmap *unit_id_map;
        Hashmap *unit_name_map;
        Set *unit_path_cache;
        uint64_t unit_cache_timestamp_hash;

        /* We don't have support for atomically enabling/disabling units, and unit_file_state might become
         * outdated if such operations failed half-way. Therefore, we set this flag if changes to unit files
         * are made, and reset it after daemon-reload. If set, we report that daemon-reload is needed through
         * unit's NeedDaemonReload property. */
        bool unit_file_state_outdated;

        char **transient_environment;  /* The environment, as determined from config files, kernel cmdline and environment generators */
        char **client_environment;     /* Environment variables created by clients through the bus API */

        usec_t watchdog[_WATCHDOG_TYPE_MAX];
        usec_t watchdog_overridden[_WATCHDOG_TYPE_MAX];
        char *watchdog_pretimeout_governor;
        char *watchdog_pretimeout_governor_overridden;

        dual_timestamp timestamps[_MANAGER_TIMESTAMP_MAX];

        /* Data specific to the device subsystem */
        sd_device_monitor *device_monitor;
        Hashmap *devices_by_sysfs;

        /* Data specific to the mount subsystem */
        struct libmnt_monitor *mount_monitor;
        sd_event_source *mount_event_source;

        /* Data specific to the swap filesystem */
        FILE *proc_swaps;
        sd_event_source *swap_event_source;
        Hashmap *swaps_by_devnode;

        /* Data specific to the D-Bus subsystem */
        sd_bus *api_bus, *system_bus;
        Set *private_buses;
        int private_listen_fd;
        sd_event_source *private_listen_event_source;

        /* Contains all the clients that are subscribed to signals via
        the API bus. Note that private bus connections are always
        considered subscribes, since they last for very short only,
        and it is much simpler that way. */
        sd_bus_track *subscribed;
        char **deserialized_subscribed;

        /* This is used during reloading: before the reload we queue
         * the reply message here, and afterwards we send it */
        sd_bus_message *pending_reload_message;

        Hashmap *watch_bus;  /* D-Bus names => Unit object n:1 */

        bool send_reloading_done;

        uint32_t current_job_id;
        uint32_t default_unit_job_id;

        /* Data specific to the Automount subsystem */
        int dev_autofs_fd;

        /* Data specific to the cgroup subsystem */
        Hashmap *cgroup_unit;
        CGroupMask cgroup_supported;
        char *cgroup_root;

        /* Notifications from cgroups, when the unified hierarchy is used is done via inotify. */
        int cgroup_inotify_fd;
        sd_event_source *cgroup_inotify_event_source;

        /* Maps for finding the unit for each inotify watch descriptor for the cgroup.events and
         * memory.events cgroupv2 attributes. */
        Hashmap *cgroup_control_inotify_wd_unit;
        Hashmap *cgroup_memory_inotify_wd_unit;

        /* A defer event for handling cgroup empty events and processing them after SIGCHLD in all cases. */
        sd_event_source *cgroup_empty_event_source;
        sd_event_source *cgroup_oom_event_source;

        /* Make sure the user cannot accidentally unmount our cgroup
         * file system */
        int pin_cgroupfs_fd;

        unsigned gc_marker;

        /* The stat() data the last time we saw /etc/localtime */
        usec_t etc_localtime_mtime;
        bool etc_localtime_accessible;

        ManagerObjective objective;

        /* Flags */
        bool dispatching_load_queue;

        /* Have we already sent out the READY=1 notification? */
        bool ready_sent;

        /* Was the last status sent "STATUS=Ready."? */
        bool status_ready;

        /* Have we already printed the taint line if necessary? */
        bool taint_logged;

        /* Have we ever changed the "kernel.pid_max" sysctl? */
        bool sysctl_pid_max_changed;

        ManagerTestRunFlags test_run_flags;

        /* If non-zero, exit with the following value when the systemd
         * process terminate. Useful for containers: systemd-nspawn could get
         * the return value. */
        uint8_t return_value;

        ShowStatus show_status;
        ShowStatus show_status_overridden;
        StatusUnitFormat status_unit_format;
        char *confirm_spawn;
        bool no_console_output;
        bool service_watchdogs;

        UnitDefaults defaults;

        int original_log_level;
        LogTarget original_log_target;
        bool log_level_overridden;
        bool log_target_overridden;

        /* non-zero if we are reloading or reexecuting, */
        int n_reloading;

        unsigned n_installed_jobs;
        unsigned n_failed_jobs;

        /* Jobs in progress watching */
        unsigned n_running_jobs;
        unsigned n_on_console;
        unsigned jobs_in_progress_iteration;

        /* Do we have any outstanding password prompts? */
        int have_ask_password;
        int ask_password_inotify_fd;
        sd_event_source *ask_password_event_source;

        /* Type=idle pipes */
        int idle_pipe[4];
        sd_event_source *idle_pipe_event_source;

        char *switch_root;
        char *switch_root_init;

        /* This is true before and after switching root. */
        bool switching_root;

        /* These map all possible path prefixes to the units needing them. They are hashmaps with a path
         * string as key, and a Set as value where Unit objects are contained. */
        Hashmap *units_needing_mounts_for[_UNIT_MOUNT_DEPENDENCY_TYPE_MAX];

        /* Used for processing polkit authorization responses */
        Hashmap *polkit_registry;

        /* Dynamic users/groups, indexed by their name */
        Hashmap *dynamic_users;

        /* Keep track of all UIDs and GIDs any of our services currently use. This is useful for the RemoveIPC= logic. */
        Hashmap *uid_refs;
        Hashmap *gid_refs;

        /* ExecSharedRuntime, indexed by their owner unit id */
        Hashmap *exec_shared_runtime_by_id;

        /* When the user hits C-A-D more than 7 times per 2s, do something immediately... */
        RateLimit ctrl_alt_del_ratelimit;
        EmergencyAction cad_burst_action;

        const char *unit_log_field;
        const char *unit_log_format_string;

        const char *invocation_log_field;
        const char *invocation_log_format_string;

        int first_boot; /* tri-state */

        /* Prefixes of e.g. RuntimeDirectory= */
        char *prefix[_EXEC_DIRECTORY_TYPE_MAX];
        char *received_credentials_directory;
        char *received_encrypted_credentials_directory;

        /* Used in the SIGCHLD and sd_notify() message invocation logic to avoid that we dispatch the same event
         * multiple times on the same unit. */
        unsigned sigchldgen;
        unsigned notifygen;

        VarlinkServer *varlink_server;
        /* When we're a system manager, this object manages the subscription from systemd-oomd to PID1 that's
         * used to report changes in ManagedOOM settings (systemd server - oomd client). When
         * we're a user manager, this object manages the client connection from the user manager to
         * systemd-oomd to report changes in ManagedOOM settings (systemd client - oomd server). */
        Varlink *managed_oom_varlink;

        /* Reference to RestrictFileSystems= BPF program */
        struct restrict_fs_bpf *restrict_fs;

        /* Allow users to configure a rate limit for Reload() operations */
        RateLimit reload_ratelimit;
        /* Dump*() are slow, so always rate limit them to 10 per 10 minutes */
        RateLimit dump_ratelimit;

        sd_event_source *memory_pressure_event_source;

        /* For NFTSet= */
        FirewallContext *fw_ctx;

        /* Pin the systemd-executor binary, so that it never changes until re-exec, ensuring we don't have
         * serialization/deserialization compatibility issues during upgrades. */
        int executor_fd;
};

static inline usec_t manager_default_timeout_abort_usec(Manager *m) {
        assert(m);
        return m->defaults.timeout_abort_set ? m->defaults.timeout_abort_usec : m->defaults.timeout_stop_usec;
}

#define MANAGER_IS_SYSTEM(m) ((m)->runtime_scope == RUNTIME_SCOPE_SYSTEM)
#define MANAGER_IS_USER(m) ((m)->runtime_scope == RUNTIME_SCOPE_USER)

#define MANAGER_IS_RELOADING(m) ((m)->n_reloading > 0)

#define MANAGER_IS_FINISHED(m) (dual_timestamp_is_set((m)->timestamps + MANAGER_TIMESTAMP_FINISH))

/* The objective is set to OK as soon as we enter the main loop, and set otherwise as soon as we are done with it */
#define MANAGER_IS_RUNNING(m) ((m)->objective == MANAGER_OK)

#define MANAGER_IS_SWITCHING_ROOT(m) ((m)->switching_root)

#define MANAGER_IS_TEST_RUN(m) ((m)->test_run_flags != 0)

static inline usec_t manager_default_timeout(RuntimeScope scope) {
        return scope == RUNTIME_SCOPE_SYSTEM ? DEFAULT_TIMEOUT_USEC : DEFAULT_USER_TIMEOUT_USEC;
}

int manager_new(RuntimeScope scope, ManagerTestRunFlags test_run_flags, Manager **m);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m, FILE *serialization, FDSet *fds, const char *root);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j);

bool manager_unit_cache_should_retry_load(Unit *u);
int manager_load_unit_prepare(Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **ret);
int manager_load_unit(Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **ret);
int manager_load_startable_unit_or_warn(Manager *m, const char *name, const char *path, Unit **ret);
int manager_load_unit_from_dbus_path(Manager *m, const char *s, sd_bus_error *e, Unit **_u);

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, Set *affected_jobs, sd_bus_error *e, Job **_ret);
int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, Set *affected_jobs, sd_bus_error *e, Job **_ret);
int manager_add_job_by_name_and_warn(Manager *m, JobType type, const char *name, JobMode mode, Set *affected_jobs,  Job **ret);
int manager_propagate_reload(Manager *m, Unit *unit, JobMode mode, sd_bus_error *e);

void manager_clear_jobs(Manager *m);

void manager_unwatch_pidref(Manager *m, PidRef *pid);

unsigned manager_dispatch_load_queue(Manager *m);

int manager_setup_memory_pressure_event_source(Manager *m);

int manager_default_environment(Manager *m);
int manager_transient_environment_add(Manager *m, char **plus);
int manager_client_environment_modify(Manager *m, char **minus, char **plus);
int manager_get_effective_environment(Manager *m, char ***ret);

int manager_set_unit_defaults(Manager *m, const UnitDefaults *defaults);

void manager_trigger_run_queue(Manager *m);

int manager_loop(Manager *m);

int manager_reload(Manager *m);
Manager* manager_reloading_start(Manager *m);
void manager_reloading_stopp(Manager **m);

void manager_reset_failed(Manager *m);

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success);
void manager_send_unit_plymouth(Manager *m, Unit *u);

bool manager_unit_inactive_or_pending(Manager *m, const char *name);

void manager_check_finished(Manager *m);
void manager_send_reloading(Manager *m);

void disable_printk_ratelimit(void);
void manager_recheck_dbus(Manager *m);
void manager_recheck_journal(Manager *m);

bool manager_get_show_status_on(Manager *m);
void manager_set_show_status(Manager *m, ShowStatus mode, const char *reason);
void manager_override_show_status(Manager *m, ShowStatus mode, const char *reason);

void manager_set_first_boot(Manager *m, bool b);
void manager_set_switching_root(Manager *m, bool switching_root);

double manager_get_progress(Manager *m);

void manager_status_printf(Manager *m, StatusType type, const char *status, const char *format, ...) _printf_(4,5);

Set* manager_get_units_needing_mounts_for(Manager *m, const char *path, UnitMountDependencyType t);

ManagerState manager_state(Manager *m);

int manager_update_failed_units(Manager *m, Unit *u, bool failed);

void manager_unref_uid(Manager *m, uid_t uid, bool destroy_now);
int manager_ref_uid(Manager *m, uid_t uid, bool clean_ipc);

void manager_unref_gid(Manager *m, gid_t gid, bool destroy_now);
int manager_ref_gid(Manager *m, gid_t gid, bool clean_ipc);

char* manager_taint_string(const Manager *m);

void manager_ref_console(Manager *m);
void manager_unref_console(Manager *m);

void manager_override_log_level(Manager *m, int level);
void manager_restore_original_log_level(Manager *m);

void manager_override_log_target(Manager *m, LogTarget target);
void manager_restore_original_log_target(Manager *m);

const char *manager_state_to_string(ManagerState m) _const_;
ManagerState manager_state_from_string(const char *s) _pure_;

const char *manager_get_confirm_spawn(Manager *m);
void manager_disable_confirm_spawn(void);

const char *manager_timestamp_to_string(ManagerTimestamp m) _const_;
ManagerTimestamp manager_timestamp_from_string(const char *s) _pure_;
ManagerTimestamp manager_timestamp_initrd_mangle(ManagerTimestamp s);

usec_t manager_get_watchdog(Manager *m, WatchdogType t);
void manager_set_watchdog(Manager *m, WatchdogType t, usec_t timeout);
void manager_override_watchdog(Manager *m, WatchdogType t, usec_t timeout);
int manager_set_watchdog_pretimeout_governor(Manager *m, const char *governor);
int manager_override_watchdog_pretimeout_governor(Manager *m, const char *governor);

LogTarget manager_get_executor_log_target(Manager *m);

int manager_allocate_idle_pipe(Manager *m);

const char* oom_policy_to_string(OOMPolicy i) _const_;
OOMPolicy oom_policy_from_string(const char *s) _pure_;

void unit_defaults_init(UnitDefaults *defaults, RuntimeScope scope);
void unit_defaults_done(UnitDefaults *defaults);
