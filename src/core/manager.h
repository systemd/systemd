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
#include <stdio.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "fdset.h"
#include "cgroup-util.h"
#include "hashmap.h"
#include "list.h"
#include "ratelimit.h"

/* Enforce upper limit how many names we allow */
#define MANAGER_MAX_NAMES 131072 /* 128K */

typedef struct Manager Manager;

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

typedef enum ManagerExitCode {
        MANAGER_OK,
        MANAGER_EXIT,
        MANAGER_RELOAD,
        MANAGER_REEXECUTE,
        MANAGER_REBOOT,
        MANAGER_POWEROFF,
        MANAGER_HALT,
        MANAGER_KEXEC,
        MANAGER_SWITCH_ROOT,
        _MANAGER_EXIT_CODE_MAX,
        _MANAGER_EXIT_CODE_INVALID = -1
} ManagerExitCode;

typedef enum StatusType {
        STATUS_TYPE_EPHEMERAL,
        STATUS_TYPE_NORMAL,
        STATUS_TYPE_EMERGENCY,
} StatusType;

#include "job.h"
#include "path-lookup.h"
#include "execute.h"
#include "unit-name.h"
#include "show-status.h"

struct Manager {
        /* Note that the set of units we know of is allowed to be
         * inconsistent. However the subset of it that is loaded may
         * not, and the list of jobs may neither. */

        /* Active jobs and units */
        Hashmap *units;  /* name string => Unit object n:1 */
        Hashmap *jobs;   /* job id => Job object 1:1 */

        /* To make it easy to iterate through the units of a specific
         * type we maintain a per type linked list */
        LIST_HEAD(Unit, units_by_type[_UNIT_TYPE_MAX]);

        /* Units that need to be loaded */
        LIST_HEAD(Unit, load_queue); /* this is actually more a stack than a queue, but uh. */

        /* Jobs that need to be run */
        LIST_HEAD(Job, run_queue);   /* more a stack than a queue, too */

        /* Units and jobs that have not yet been announced via
         * D-Bus. When something about a job changes it is added here
         * if it is not in there yet. This allows easy coalescing of
         * D-Bus change signals. */
        LIST_HEAD(Unit, dbus_unit_queue);
        LIST_HEAD(Job, dbus_job_queue);

        /* Units to remove */
        LIST_HEAD(Unit, cleanup_queue);

        /* Units to check when doing GC */
        LIST_HEAD(Unit, gc_queue);

        /* Units that should be realized */
        LIST_HEAD(Unit, cgroup_queue);

        sd_event *event;

        /* We use two hash tables here, since the same PID might be
         * watched by two different units: once the unit that forked
         * it off, and possibly a different unit to which it was
         * joined as cgroup member. Since we know that it is either
         * one or two units for each PID we just use to hashmaps
         * here. */
        Hashmap *watch_pids1;  /* pid => Unit object n:1 */
        Hashmap *watch_pids2;  /* pid => Unit object n:1 */

        /* A set contains all units which cgroup should be refreshed after startup */
        Set *startup_units;

        /* A set which contains all currently failed units */
        Set *failed_units;

        sd_event_source *run_queue_event_source;

        char *notify_socket;
        int notify_fd;
        sd_event_source *notify_event_source;

        int signal_fd;
        sd_event_source *signal_event_source;

        int time_change_fd;
        sd_event_source *time_change_event_source;

        sd_event_source *jobs_in_progress_event_source;

        unsigned n_snapshots;

        LookupPaths lookup_paths;
        Set *unit_path_cache;

        char **environment;

        usec_t runtime_watchdog;
        usec_t shutdown_watchdog;

        dual_timestamp firmware_timestamp;
        dual_timestamp loader_timestamp;
        dual_timestamp kernel_timestamp;
        dual_timestamp initrd_timestamp;
        dual_timestamp userspace_timestamp;
        dual_timestamp finish_timestamp;

        dual_timestamp security_start_timestamp;
        dual_timestamp security_finish_timestamp;
        dual_timestamp generators_start_timestamp;
        dual_timestamp generators_finish_timestamp;
        dual_timestamp units_load_start_timestamp;
        dual_timestamp units_load_finish_timestamp;

        char *generator_unit_path;
        char *generator_unit_path_early;
        char *generator_unit_path_late;

        struct udev* udev;

        /* Data specific to the device subsystem */
        struct udev_monitor* udev_monitor;
        sd_event_source *udev_event_source;
        Hashmap *devices_by_sysfs;

        /* Data specific to the mount subsystem */
        FILE *proc_self_mountinfo;
        sd_event_source *mount_event_source;
        int utab_inotify_fd;
        sd_event_source *mount_utab_event_source;

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
        sd_bus_message *queued_message;

        Hashmap *watch_bus;  /* D-Bus names => Unit object n:1 */

        bool send_reloading_done;

        uint32_t current_job_id;
        uint32_t default_unit_job_id;

        /* Data specific to the Automount subsystem */
        int dev_autofs_fd;

        /* Data specific to the cgroup subsystem */
        Hashmap *cgroup_unit;
        CGroupControllerMask cgroup_supported;
        char *cgroup_root;

        int gc_marker;
        unsigned n_in_gc_queue;

        /* Make sure the user cannot accidentally unmount our cgroup
         * file system */
        int pin_cgroupfs_fd;

        /* Flags */
        ManagerRunningAs running_as;
        ManagerExitCode exit_code:5;

        bool dispatching_load_queue:1;
        bool dispatching_dbus_queue:1;

        bool taint_usr:1;
        bool first_boot:1;

        bool test_run:1;

        ShowStatus show_status;
        bool confirm_spawn;
        bool no_console_output;

        ExecOutput default_std_output, default_std_error;

        usec_t default_restart_usec, default_timeout_start_usec, default_timeout_stop_usec;

        usec_t default_start_limit_interval;
        unsigned default_start_limit_burst;

        bool default_cpu_accounting;
        bool default_memory_accounting;
        bool default_blockio_accounting;

        usec_t default_timer_accuracy_usec;

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

        /* Reference to the kdbus bus control fd */
        int kdbus_fd;

        /* Used for processing polkit authorization responses */
        Hashmap *polkit_registry;

        /* When the user hits C-A-D more than 7 times per 2s, reboot immediately... */
        RateLimit ctrl_alt_del_ratelimit;

        const char *unit_log_field;
        const char *unit_log_format_string;
};

int manager_new(ManagerRunningAs running_as, bool test_run, Manager **m);
Manager* manager_free(Manager *m);

int manager_enumerate(Manager *m);
int manager_startup(Manager *m, FILE *serialization, FDSet *fds);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_get_unit_by_path(Manager *m, const char *path, const char *suffix, Unit **_found);

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j);

int manager_load_unit_prepare(Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **_ret);
int manager_load_unit(Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **_ret);
int manager_load_unit_from_dbus_path(Manager *m, const char *s, sd_bus_error *e, Unit **_u);

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool force, sd_bus_error *e, Job **_ret);
int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool force, sd_bus_error *e, Job **_ret);

void manager_dump_units(Manager *s, FILE *f, const char *prefix);
void manager_dump_jobs(Manager *s, FILE *f, const char *prefix);

void manager_clear_jobs(Manager *m);

unsigned manager_dispatch_load_queue(Manager *m);

int manager_environment_add(Manager *m, char **minus, char **plus);
int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit);

int manager_loop(Manager *m);

void manager_dispatch_bus_name_owner_changed(Manager *m, const char *name, const char* old_owner, const char *new_owner);

int manager_open_serialization(Manager *m, FILE **_f);

int manager_serialize(Manager *m, FILE *f, FDSet *fds, bool switching_root);
int manager_deserialize(Manager *m, FILE *f, FDSet *fds);

int manager_reload(Manager *m);

bool manager_is_reloading_or_reexecuting(Manager *m) _pure_;

void manager_reset_failed(Manager *m);

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success);
void manager_send_unit_plymouth(Manager *m, Unit *u);

bool manager_unit_inactive_or_pending(Manager *m, const char *name);

void manager_check_finished(Manager *m);

void manager_recheck_journal(Manager *m);

void manager_set_show_status(Manager *m, ShowStatus mode);
void manager_set_first_boot(Manager *m, bool b);

void manager_status_printf(Manager *m, StatusType type, const char *status, const char *format, ...) _printf_(4,5);
void manager_flip_auto_status(Manager *m, bool enable);

Set *manager_get_units_requiring_mounts_for(Manager *m, const char *path);

const char *manager_get_runtime_prefix(Manager *m);

ManagerState manager_state(Manager *m);

void manager_update_failed_units(Manager *m, Unit *u, bool failed);

const char *manager_state_to_string(ManagerState m) _const_;
ManagerState manager_state_from_string(const char *s) _pure_;
