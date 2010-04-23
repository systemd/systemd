/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foomanagerhfoo
#define foomanagerhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <dbus/dbus.h>

#include "fdset.h"

/* Enforce upper limit how many names we allow */
#define MANAGER_MAX_NAMES 2048

typedef struct Manager Manager;
typedef enum WatchType WatchType;
typedef struct Watch Watch;

typedef enum ManagerExitCode {
        MANAGER_RUNNING,
        MANAGER_EXIT,
        MANAGER_RELOAD,
        MANAGER_REEXECUTE,
        _MANAGER_EXIT_CODE_MAX,
        _MANAGER_EXIT_CODE_INVALID = -1
} ManagerExitCode;

typedef enum ManagerRunningAs {
        MANAGER_INIT,      /* root and pid=1 */
        MANAGER_SYSTEM,    /* root and pid!=1 */
        MANAGER_SESSION,   /* non-root, for a session */
        _MANAGER_RUNNING_AS_MAX,
        _MANAGER_RUNNING_AS_INVALID = -1
} ManagerRunningAs;

enum WatchType {
        WATCH_INVALID,
        WATCH_SIGNAL,
        WATCH_FD,
        WATCH_TIMER,
        WATCH_MOUNT,
        WATCH_UDEV,
        WATCH_DBUS_WATCH,
        WATCH_DBUS_TIMEOUT
};

struct Watch {
        int fd;
        WatchType type;
        union {
                union Unit *unit;
                DBusWatch *bus_watch;
                DBusTimeout *bus_timeout;
                bool socket_accept;
        } data;
        bool fd_is_dupped;
};

#include "unit.h"
#include "job.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "dbus.h"

#define SPECIAL_DEFAULT_TARGET "default.target"

/* This is not really intended to be started by directly. This is
 * mostly so that other targets (reboot/halt/poweroff) can depend on
 * it to bring all services down that want to be brought down on
 * system shutdown. */
#define SPECIAL_SHUTDOWN_TARGET "shutdown.target"

#define SPECIAL_LOGGER_SOCKET "systemd-logger.socket"

#define SPECIAL_KBREQUEST_TARGET "kbrequest.target"
#define SPECIAL_SIGPWR_TARGET "sigpwr.target"
#define SPECIAL_CTRL_ALT_DEL_TARGET "ctrl-alt-del.target"

#define SPECIAL_LOCAL_FS_TARGET "local-fs.target"
#define SPECIAL_REMOTE_FS_TARGET "remote-fs.target"
#define SPECIAL_NETWORK_TARGET "network.target"
#define SPECIAL_NSS_LOOKUP_TARGET "nss-lookup.target"     /* LSB's $named */
#define SPECIAL_RPCBIND_TARGET "rpcbind.target"           /* LSB's $portmap */
#define SPECIAL_SYSLOG_TARGET "syslog.target"             /* Should pull in syslog.socket or syslog.service */
#define SPECIAL_RTC_SET_TARGET "rtc-set.target"           /* LSB's $time */

#define SPECIAL_BASIC_TARGET "basic.target"
#define SPECIAL_RESCUE_TARGET "rescue.target"

#ifndef SPECIAL_DBUS_SERVICE
#define SPECIAL_DBUS_SERVICE "dbus.service"
#endif

#ifndef SPECIAL_SYSLOG_SERVICE
#define SPECIAL_SYSLOG_SERVICE "syslog.service"
#endif

/* For SysV compatibility. Usually an alias for a saner target. On
 * SysV-free systems this doesn't exist. */
#define SPECIAL_RUNLEVEL0_TARGET "runlevel0.target"
#define SPECIAL_RUNLEVEL1_TARGET "runlevel1.target"
#define SPECIAL_RUNLEVEL2_TARGET "runlevel2.target"
#define SPECIAL_RUNLEVEL3_TARGET "runlevel3.target"
#define SPECIAL_RUNLEVEL4_TARGET "runlevel4.target"
#define SPECIAL_RUNLEVEL5_TARGET "runlevel5.target"
#define SPECIAL_RUNLEVEL6_TARGET "runlevel6.target"

struct Manager {
        uint32_t current_job_id;

        /* Note that the set of units we know of is allowed to be
         * incosistent. However the subset of it that is loaded may
         * not, and the list of jobs may neither. */

        /* Active jobs and units */
        Hashmap *units;  /* name string => Unit object n:1 */
        Hashmap *jobs;   /* job id => Job object 1:1 */

        /* To make it easy to iterate through the units of a specific
         * type we maintain a per type linked list */
        LIST_HEAD(Meta, units_per_type[_UNIT_TYPE_MAX]);

        /* Units that need to be loaded */
        LIST_HEAD(Meta, load_queue); /* this is actually more a stack than a queue, but uh. */

        /* Jobs that need to be run */
        LIST_HEAD(Job, run_queue);   /* more a stack than a queue, too */

        /* Units and jobs that have not yet been announced via
         * D-Bus. When something about a job changes it is added here
         * if it is not in there yet. This allows easy coalescing of
         * D-Bus change signals. */
        LIST_HEAD(Meta, dbus_unit_queue);
        LIST_HEAD(Job, dbus_job_queue);

        /* Units to remove */
        LIST_HEAD(Meta, cleanup_queue);

        /* Units to check when doing GC */
        LIST_HEAD(Meta, gc_queue);

        /* Jobs to be added */
        Hashmap *transaction_jobs;      /* Unit object => Job object list 1:1 */
        JobDependency *transaction_anchor;

        Hashmap *watch_pids;  /* pid => Unit object n:1 */

        Watch signal_watch;

        int epoll_fd;

        unsigned n_snapshots;

        char **unit_path;
        char **sysvinit_path;
        char **sysvrcnd_path;

        usec_t boot_timestamp;

        /* Data specific to the device subsystem */
        struct udev* udev;
        struct udev_monitor* udev_monitor;
        Watch udev_watch;

        /* Data specific to the mount subsystem */
        FILE *proc_self_mountinfo;
        Watch mount_watch;

        /* Data specific to the D-Bus subsystem */
        DBusConnection *api_bus, *system_bus;
        Set *subscribed;
        DBusMessage *queued_message; /* This is used during reloading:
                                      * before the reload we queue the
                                      * reply message here, and
                                      * afterwards we send it */

        Hashmap *watch_bus;  /* D-Bus names => Unit object n:1 */
        int32_t name_data_slot;

        /* Data specific to the Automount subsystem */
        int dev_autofs_fd;

        /* Data specific to the cgroup subsystem */
        Hashmap *cgroup_bondings; /* path string => CGroupBonding object 1:n */
        char *cgroup_controller;
        char *cgroup_hierarchy;

        usec_t gc_queue_timestamp;

        int gc_marker;
        unsigned n_in_gc_queue;

        /* Flags */
        ManagerRunningAs running_as;
        ManagerExitCode exit_code:4;

        bool dispatching_load_queue:1;
        bool dispatching_run_queue:1;
        bool dispatching_dbus_queue:1;

        bool request_api_bus_dispatch:1;
        bool request_system_bus_dispatch:1;

        bool utmp_reboot_written:1;

        bool confirm_spawn:1;
};

int manager_new(ManagerRunningAs running_as, bool confirm_spawn, Manager **m);
void manager_free(Manager *m);

int manager_enumerate(Manager *m);
int manager_coldplug(Manager *m);
int manager_startup(Manager *m, FILE *serialization, FDSet *fds);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_get_unit_from_dbus_path(Manager *m, const char *s, Unit **_u);
int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j);

int manager_load_unit(Manager *m, const char *name, const char *path, Unit **_ret);

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool force, Job **_ret);
int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool force, Job **_ret);

void manager_dump_units(Manager *s, FILE *f, const char *prefix);
void manager_dump_jobs(Manager *s, FILE *f, const char *prefix);

void manager_transaction_unlink_job(Manager *m, Job *j, bool delete_dependencies);

void manager_clear_jobs(Manager *m);

unsigned manager_dispatch_load_queue(Manager *m);
unsigned manager_dispatch_run_queue(Manager *m);
unsigned manager_dispatch_dbus_queue(Manager *m);

int manager_loop(Manager *m);

void manager_write_utmp_reboot(Manager *m);
void manager_write_utmp_runlevel(Manager *m, Unit *t);

void manager_dispatch_bus_name_owner_changed(Manager *m, const char *name, const char* old_owner, const char *new_owner);
void manager_dispatch_bus_query_pid_done(Manager *m, const char *name, pid_t pid);

int manager_open_serialization(FILE **_f);

int manager_serialize(Manager *m, FILE *f, FDSet *fds);
int manager_deserialize(Manager *m, FILE *f, FDSet *fds);

int manager_reload(Manager *m);

const char *manager_running_as_to_string(ManagerRunningAs i);
ManagerRunningAs manager_running_as_from_string(const char *s);

#endif
