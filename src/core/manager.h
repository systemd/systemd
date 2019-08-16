/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"

#include "cgroup-util.h"
#include "fdset.h"
#include "hashmap.h"
#include "ip-address-access.h"
#include "list.h"
#include "prioq.h"
#include "ratelimit.h"

struct libmnt_monitor;
typedef struct Unit Unit;

/* Enforce upper limit how many names we allow */
#define MANAGER_MAX_NAMES 131072 /* 128K */

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
        _MANAGER_STATE_INVALID = -1
} ManagerState;

typedef enum ManagerObjective {
        MANAGER_OK,
        MANAGER_EXIT,
        MANAGER_RELOAD,
        MANAGER_REEXECUTE,
        MANAGER_REBOOT,
        MANAGER_POWEROFF,
        MANAGER_HALT,
        MANAGER_KEXEC,
        MANAGER_SWITCH_ROOT,
        _MANAGER_OBJECTIVE_MAX,
        _MANAGER_OBJECTIVE_INVALID = -1
} ManagerObjective;

typedef enum StatusType {
        STATUS_TYPE_EPHEMERAL,
        STATUS_TYPE_NORMAL,
        STATUS_TYPE_EMERGENCY,
} StatusType;

typedef enum OOMPolicy {
        OOM_CONTINUE,          /* The kernel kills the process it wants to kill, and that's it */
        OOM_STOP,              /* The kernel kills the process it wants to kill, and we stop the unit */
        OOM_KILL,              /* The kernel kills the process it wants to kill, and all others in the unit, and we stop the unit */
        _OOM_POLICY_MAX,
        _OOM_POLICY_INVALID = -1
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

        MANAGER_TIMESTAMP_INITRD_SECURITY_START,
        MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH,
        MANAGER_TIMESTAMP_INITRD_GENERATORS_START,
        MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH,
        MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START,
        MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH,
        _MANAGER_TIMESTAMP_MAX,
        _MANAGER_TIMESTAMP_INVALID = -1,
} ManagerTimestamp;

#include "execute.h"
#include "job.h"
#include "path-lookup.h"
#include "show-status.h"
#include "unit-name.h"

typedef enum ManagerTestRunFlags {
        MANAGER_TEST_NORMAL             = 0,       /* run normally */
        MANAGER_TEST_RUN_MINIMAL        = 1 << 0,  /* create basic data structures */
        MANAGER_TEST_RUN_BASIC          = 1 << 1,  /* interact with the environment */
        MANAGER_TEST_RUN_ENV_GENERATORS = 1 << 2,  /* also run env generators  */
        MANAGER_TEST_RUN_GENERATORS     = 1 << 3,  /* also run unit generators */
        MANAGER_TEST_FULL = MANAGER_TEST_RUN_BASIC | MANAGER_TEST_RUN_ENV_GENERATORS | MANAGER_TEST_RUN_GENERATORS,
} ManagerTestRunFlags;

assert_cc((MANAGER_TEST_FULL & UINT8_MAX) == MANAGER_TEST_FULL);

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

        sd_event *event;

        /* This maps PIDs we care about to units that are interested in. We allow multiple units to he interested in
         * the same PID and multiple PIDs to be relevant to the same unit. Since in most cases only a single unit will
         * be interested in the same PID we use a somewhat special encoding here: the first unit interested in a PID is
         * stored directly in the hashmap, keyed by the PID unmodified. If there are other units interested too they'll
         * be stored in a NULL-terminated array, and keyed by the negative PID. This is safe as pid_t is signed and
         * negative PIDs are not used for regular processes but process groups, which we don't care about in this
         * context, but this allows us to use the negative range for our own purposes. */
        Hashmap *watch_pids;  /* pid => unit as well as -pid => array of units */

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

        int time_change_fd;
        sd_event_source *time_change_event_source;

        sd_event_source *timezone_change_event_source;

        sd_event_source *jobs_in_progress_event_source;

        int user_lookup_fds[2];
        sd_event_source *user_lookup_event_source;

        sd_event_source *sync_bus_names_event_source;

        UnitFileScope unit_file_scope;
        LookupPaths lookup_paths;
        Hashmap *unit_id_map;
        Hashmap *unit_name_map;
        Set *unit_path_cache;
        usec_t unit_cache_mtime;

        char **transient_environment;  /* The environment, as determined from config files, kernel cmdline and environment generators */
        char **client_environment;     /* Environment variables created by clients through the bus API */

        usec_t runtime_watchdog;
        usec_t reboot_watchdog;
        usec_t kexec_watchdog;

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
        bool etc_localtime_accessible:1;

        ManagerObjective objective:5;

        /* Flags */
        bool dispatching_load_queue:1;

        bool taint_usr:1;

        /* Have we already sent out the READY=1 notification? */
        bool ready_sent:1;

        /* Have we already printed the taint line if necessary? */
        bool taint_logged:1;

        /* Have we ever changed the "kernel.pid_max" sysctl? */
        bool sysctl_pid_max_changed:1;

        ManagerTestRunFlags test_run_flags:8;

        /* If non-zero, exit with the following value when the systemd
         * process terminate. Useful for containers: systemd-nspawn could get
         * the return value. */
        uint8_t return_value;

        ShowStatus show_status;
        StatusUnitFormat status_unit_format;
        char *confirm_spawn;
        bool no_console_output;
        bool service_watchdogs;

        ExecOutput default_std_output, default_std_error;

        usec_t default_restart_usec, default_timeout_start_usec, default_timeout_stop_usec;
        usec_t default_timeout_abort_usec;
        bool default_timeout_abort_set;

        usec_t default_start_limit_interval;
        unsigned default_start_limit_burst;

        bool default_cpu_accounting;
        bool default_memory_accounting;
        bool default_io_accounting;
        bool default_blockio_accounting;
        bool default_tasks_accounting;
        bool default_ip_accounting;

        uint64_t default_tasks_max;
        usec_t default_timer_accuracy_usec;

        OOMPolicy default_oom_policy;

        int original_log_level;
        LogTarget original_log_target;
        bool log_level_overridden:1;
        bool log_target_overridden:1;

        struct rlimit *rlimit[_RLIMIT_MAX];

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

        /* This maps all possible path prefixes to the units needing
         * them. It's a hashmap with a path string as key and a Set as
         * value where Unit objects are contained. */
        Hashmap *units_requiring_mounts_for;

        /* Used for processing polkit authorization responses */
        Hashmap *polkit_registry;

        /* Dynamic users/groups, indexed by their name */
        Hashmap *dynamic_users;

        /* Keep track of all UIDs and GIDs any of our services currently use. This is useful for the RemoveIPC= logic. */
        Hashmap *uid_refs;
        Hashmap *gid_refs;

        /* ExecRuntime, indexed by their owner unit id */
        Hashmap *exec_runtime_by_id;

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

        /* Used in the SIGCHLD and sd_notify() message invocation logic to avoid that we dispatch the same event
         * multiple times on the same unit. */
        unsigned sigchldgen;
        unsigned notifygen;

        bool honor_device_enumeration;
};

static inline usec_t manager_default_timeout_abort_usec(Manager *m) {
        assert(m);
        return m->default_timeout_abort_set ? m->default_timeout_abort_usec : m->default_timeout_stop_usec;
}

#define MANAGER_IS_SYSTEM(m) ((m)->unit_file_scope == UNIT_FILE_SYSTEM)
#define MANAGER_IS_USER(m) ((m)->unit_file_scope != UNIT_FILE_SYSTEM)

#define MANAGER_IS_RELOADING(m) ((m)->n_reloading > 0)

#define MANAGER_IS_FINISHED(m) (dual_timestamp_is_set((m)->timestamps + MANAGER_TIMESTAMP_FINISH))

/* The objective is set to OK as soon as we enter the main loop, and set otherwise as soon as we are done with it */
#define MANAGER_IS_RUNNING(m) ((m)->objective == MANAGER_OK)

#define MANAGER_IS_TEST_RUN(m) ((m)->test_run_flags != 0)

int manager_new(UnitFileScope scope, ManagerTestRunFlags test_run_flags, Manager **m);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m, FILE *serialization, FDSet *fds);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j);

int manager_load_unit_prepare(Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **_ret);
int manager_load_unit(Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **_ret);
int manager_load_startable_unit_or_warn(Manager *m, const char *name, const char *path, Unit **ret);
int manager_load_unit_from_dbus_path(Manager *m, const char *s, sd_bus_error *e, Unit **_u);

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, Set *affected_jobs, sd_bus_error *e, Job **_ret);
int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, Set *affected_jobs, sd_bus_error *e, Job **_ret);
int manager_add_job_by_name_and_warn(Manager *m, JobType type, const char *name, JobMode mode, Set *affected_jobs,  Job **ret);
int manager_propagate_reload(Manager *m, Unit *unit, JobMode mode, sd_bus_error *e);

void manager_dump_units(Manager *s, FILE *f, const char *prefix);
void manager_dump_jobs(Manager *s, FILE *f, const char *prefix);
void manager_dump(Manager *s, FILE *f, const char *prefix);
int manager_get_dump_string(Manager *m, char **ret);

void manager_clear_jobs(Manager *m);

void manager_unwatch_pid(Manager *m, pid_t pid);

unsigned manager_dispatch_load_queue(Manager *m);

int manager_default_environment(Manager *m);
int manager_transient_environment_add(Manager *m, char **plus);
int manager_client_environment_modify(Manager *m, char **minus, char **plus);
int manager_get_effective_environment(Manager *m, char ***ret);

int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit);

int manager_loop(Manager *m);

int manager_open_serialization(Manager *m, FILE **_f);

int manager_serialize(Manager *m, FILE *f, FDSet *fds, bool switching_root);
int manager_deserialize(Manager *m, FILE *f, FDSet *fds);

int manager_reload(Manager *m);

void manager_reset_failed(Manager *m);

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success);
void manager_send_unit_plymouth(Manager *m, Unit *u);

bool manager_unit_inactive_or_pending(Manager *m, const char *name);

void manager_check_finished(Manager *m);

void manager_recheck_dbus(Manager *m);
void manager_recheck_journal(Manager *m);

void manager_set_show_status(Manager *m, ShowStatus mode);
void manager_set_first_boot(Manager *m, bool b);

void manager_status_printf(Manager *m, StatusType type, const char *status, const char *format, ...) _printf_(4,5);
void manager_flip_auto_status(Manager *m, bool enable);

Set *manager_get_units_requiring_mounts_for(Manager *m, const char *path);

ManagerState manager_state(Manager *m);

int manager_update_failed_units(Manager *m, Unit *u, bool failed);

void manager_unref_uid(Manager *m, uid_t uid, bool destroy_now);
int manager_ref_uid(Manager *m, uid_t uid, bool clean_ipc);

void manager_unref_gid(Manager *m, gid_t gid, bool destroy_now);
int manager_ref_gid(Manager *m, gid_t gid, bool destroy_now);

void manager_vacuum_uid_refs(Manager *m);
void manager_vacuum_gid_refs(Manager *m);

void manager_serialize_uid_refs(Manager *m, FILE *f);
void manager_deserialize_uid_refs_one(Manager *m, const char *value);

void manager_serialize_gid_refs(Manager *m, FILE *f);
void manager_deserialize_gid_refs_one(Manager *m, const char *value);

char *manager_taint_string(Manager *m);

void manager_ref_console(Manager *m);
void manager_unref_console(Manager *m);

void manager_override_log_level(Manager *m, int level);
void manager_restore_original_log_level(Manager *m);

void manager_override_log_target(Manager *m, LogTarget target);
void manager_restore_original_log_target(Manager *m);

const char *manager_state_to_string(ManagerState m) _const_;
ManagerState manager_state_from_string(const char *s) _pure_;

const char *manager_get_confirm_spawn(Manager *m);
bool manager_is_confirm_spawn_disabled(Manager *m);
void manager_disable_confirm_spawn(void);

const char *manager_timestamp_to_string(ManagerTimestamp m) _const_;
ManagerTimestamp manager_timestamp_from_string(const char *s) _pure_;
ManagerTimestamp manager_timestamp_initrd_mangle(ManagerTimestamp s);

const char* oom_policy_to_string(OOMPolicy i) _const_;
OOMPolicy oom_policy_from_string(const char *s) _pure_;
