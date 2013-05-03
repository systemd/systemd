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
#include <inttypes.h>
#include <stdio.h>
#include <dbus/dbus.h>

#include "fdset.h"

/* Enforce upper limit how many names we allow */
#define MANAGER_MAX_NAMES 131072 /* 128K */

typedef struct Manager Manager;
typedef enum WatchType WatchType;
typedef struct Watch Watch;

typedef enum ManagerExitCode {
        MANAGER_RUNNING,
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

enum WatchType {
        WATCH_INVALID,
        WATCH_SIGNAL,
        WATCH_NOTIFY,
        WATCH_FD,
        WATCH_UNIT_TIMER,
        WATCH_JOB_TIMER,
        WATCH_MOUNT,
        WATCH_SWAP,
        WATCH_UDEV,
        WATCH_DBUS_WATCH,
        WATCH_DBUS_TIMEOUT,
        WATCH_TIME_CHANGE,
        WATCH_JOBS_IN_PROGRESS
};

struct Watch {
        int fd;
        WatchType type;
        union {
                struct Unit *unit;
                struct Job *job;
                DBusWatch *bus_watch;
                DBusTimeout *bus_timeout;
        } data;
        bool fd_is_dupped:1;
        bool socket_accept:1;
};

#include "unit.h"
#include "job.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "dbus.h"
#include "path-lookup.h"
#include "execute.h"

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

        /* To optimize iteration of units that have requires_mounts_for set */
        LIST_HEAD(Unit, has_requires_mounts_for);

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

        Hashmap *watch_pids;  /* pid => Unit object n:1 */

        char *notify_socket;

        Watch notify_watch;
        Watch signal_watch;
        Watch time_change_watch;
        Watch jobs_in_progress_watch;

        int epoll_fd;

        unsigned n_snapshots;

        LookupPaths lookup_paths;
        Set *unit_path_cache;

        char **environment;
        char **default_controllers;

        usec_t runtime_watchdog;
        usec_t shutdown_watchdog;

        dual_timestamp firmware_timestamp;
        dual_timestamp loader_timestamp;
        dual_timestamp kernel_timestamp;
        dual_timestamp initrd_timestamp;
        dual_timestamp userspace_timestamp;
        dual_timestamp finish_timestamp;

        char *generator_unit_path;
        char *generator_unit_path_early;
        char *generator_unit_path_late;

        /* Data specific to the device subsystem */
        struct udev* udev;
        struct udev_monitor* udev_monitor;
        Watch udev_watch;
        Hashmap *devices_by_sysfs;

        /* Data specific to the mount subsystem */
        FILE *proc_self_mountinfo;
        Watch mount_watch;

        /* Data specific to the swap filesystem */
        FILE *proc_swaps;
        Hashmap *swaps_by_proc_swaps;
        bool request_reload;
        Watch swap_watch;

        /* Data specific to the D-Bus subsystem */
        DBusConnection *api_bus, *system_bus;
        DBusServer *private_bus;
        Set *bus_connections, *bus_connections_for_dispatch;

        DBusMessage *queued_message; /* This is used during reloading:
                                      * before the reload we queue the
                                      * reply message here, and
                                      * afterwards we send it */
        DBusConnection *queued_message_connection; /* The connection to send the queued message on */

        Hashmap *watch_bus;  /* D-Bus names => Unit object n:1 */
        int32_t name_data_slot;
        int32_t conn_data_slot;
        int32_t subscribed_data_slot;

        uint32_t current_job_id;
        uint32_t default_unit_job_id;

        /* Data specific to the Automount subsystem */
        int dev_autofs_fd;

        /* Data specific to the cgroup subsystem */
        Hashmap *cgroup_bondings; /* path string => CGroupBonding object 1:n */
        char *cgroup_hierarchy;

        usec_t gc_queue_timestamp;
        int gc_marker;
        unsigned n_in_gc_queue;

        /* Make sure the user cannot accidentally unmount our cgroup
         * file system */
        int pin_cgroupfs_fd;

        /* Flags */
        SystemdRunningAs running_as;
        ManagerExitCode exit_code:5;

        bool dispatching_load_queue:1;
        bool dispatching_run_queue:1;
        bool dispatching_dbus_queue:1;

        bool taint_usr:1;

        bool show_status;
        bool confirm_spawn;

        ExecOutput default_std_output, default_std_error;

        struct rlimit *rlimit[RLIMIT_NLIMITS];

        /* non-zero if we are reloading or reexecuting, */
        int n_reloading;

        unsigned n_installed_jobs;
        unsigned n_failed_jobs;

        /* Jobs in progress watching */
        unsigned n_running_jobs;
        unsigned n_on_console;
        unsigned jobs_in_progress_iteration;

        /* Type=idle pipes */
        int idle_pipe[2];

        char *switch_root;
        char *switch_root_init;
};

int manager_new(SystemdRunningAs running_as, Manager **m);
void manager_free(Manager *m);

int manager_enumerate(Manager *m);
int manager_coldplug(Manager *m);
int manager_startup(Manager *m, FILE *serialization, FDSet *fds);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j);

int manager_load_unit_prepare(Manager *m, const char *name, const char *path, DBusError *e, Unit **_ret);
int manager_load_unit(Manager *m, const char *name, const char *path, DBusError *e, Unit **_ret);
int manager_load_unit_from_dbus_path(Manager *m, const char *s, DBusError *e, Unit **_u);

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool force, DBusError *e, Job **_ret);
int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool force, DBusError *e, Job **_ret);

void manager_dump_units(Manager *s, FILE *f, const char *prefix);
void manager_dump_jobs(Manager *s, FILE *f, const char *prefix);

void manager_clear_jobs(Manager *m);

unsigned manager_dispatch_load_queue(Manager *m);
unsigned manager_dispatch_run_queue(Manager *m);
unsigned manager_dispatch_dbus_queue(Manager *m);

int manager_set_default_controllers(Manager *m, char **controllers);
int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit);

int manager_loop(Manager *m);

void manager_dispatch_bus_name_owner_changed(Manager *m, const char *name, const char* old_owner, const char *new_owner);
void manager_dispatch_bus_query_pid_done(Manager *m, const char *name, pid_t pid);

int manager_open_serialization(Manager *m, FILE **_f);

int manager_serialize(Manager *m, FILE *f, FDSet *fds, bool switching_root);
int manager_deserialize(Manager *m, FILE *f, FDSet *fds);
int manager_distribute_fds(Manager *m, FDSet *fds);

int manager_reload(Manager *m);

bool manager_is_reloading_or_reexecuting(Manager *m) _pure_;

void manager_reset_failed(Manager *m);

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success);
void manager_send_unit_plymouth(Manager *m, Unit *u);

bool manager_unit_inactive_or_pending(Manager *m, const char *name);

void manager_check_finished(Manager *m);

void manager_run_generators(Manager *m);
void manager_undo_generators(Manager *m);

void manager_recheck_journal(Manager *m);

void manager_set_show_status(Manager *m, bool b);
void manager_status_printf(Manager *m, bool ephemeral, const char *status, const char *format, ...) _printf_attr_(4,5);

void watch_init(Watch *w);
