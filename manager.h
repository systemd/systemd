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

typedef struct Manager Manager;
typedef enum WatchType WatchType;
typedef struct Watch Watch;

typedef enum ManagerRunningAs {
        MANAGER_INIT,      /* root and pid=1 */
        MANAGER_SYSTEM,    /* root and pid!=1 */
        MANAGER_SESSION,   /* non-root */
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
        bool fd_is_dupped;
        union {
                union Unit *unit;
                DBusWatch *bus_watch;
                DBusTimeout *bus_timeout;
        } data;
};

#include "unit.h"
#include "job.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "dbus.h"

#define SPECIAL_DEFAULT_TARGET "default.target"
#define SPECIAL_SYSLOG_SERVICE "syslog.service"
#define SPECIAL_DBUS_SERVICE "messagebus.service"
#define SPECIAL_LOGGER_SOCKET "systemd-logger.socket"
#define SPECIAL_KBREQUEST_TARGET "kbrequest.target"
#define SPECIAL_CTRL_ALT_DEL_TARGET "ctrl-alt-del.target"
#define SPECIAL_LOCAL_FS_TARGET "local-fs.target"
#define SPECIAL_NETWORK_TARGET "network.target"
#define SPECIAL_NSS_LOOKUP_TARGET "nss-lookup.target"     /* LSB's $named */
#define SPECIAL_RPCBIND_TARGET "rpcbind.target"           /* LSB's $portmap */
#define SPECIAL_REMOTE_FS_TARGET "remote-fs.target"
#define SPECIAL_SYSLOG_TARGET "syslog.target"             /* Should pull in syslog.socket or syslog.service */
#define SPECIAL_RTC_SET_TARGET "rtc-set.target"           /* LSB's $time */
#define SPECIAL_SYSINIT_SERVICE "sysinit.service"

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
        /* In which mode are we running */
        ManagerRunningAs running_as;

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

        /* Jobs to be added */
        Hashmap *transaction_jobs;      /* Unit object => Job object list 1:1 */
        JobDependency *transaction_anchor;

        bool dispatching_load_queue:1;
        bool dispatching_run_queue:1;
        bool dispatching_dbus_queue:1;

        bool request_bus_dispatch:1;
        bool request_system_bus_dispatch:1;

        Hashmap *watch_pids;  /* pid => Unit object n:1 */

        int epoll_fd;

        Watch signal_watch;

        char **unit_path;
        char **sysvinit_path;

        /* Data specific to the device subsystem */
        struct udev* udev;
        struct udev_monitor* udev_monitor;
        Watch udev_watch;

        /* Data specific to the mount subsystem */
        FILE *proc_self_mountinfo;
        Watch mount_watch;

        /* Data specific to the D-Bus subsystem */
        DBusConnection *bus, *system_bus;
        Set *subscribed;

        /* Data specific to the cgroup subsystem */
        Hashmap *cgroup_bondings; /* path string => CGroupBonding object 1:n */
        char *cgroup_controller;
        char *cgroup_hierarchy;
};

int manager_new(Manager **m);
void manager_free(Manager *m);

int manager_coldplug(Manager *m);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_get_unit_from_dbus_path(Manager *m, const char *s, Unit **_u);
int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j);

int manager_load_unit(Manager *m, const char *path_or_name, Unit **_ret);
int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool force, Job **_ret);

void manager_dump_units(Manager *s, FILE *f, const char *prefix);
void manager_dump_jobs(Manager *s, FILE *f, const char *prefix);

void manager_transaction_unlink_job(Manager *m, Job *j);

void manager_clear_jobs(Manager *m);

unsigned manager_dispatch_load_queue(Manager *m);
unsigned manager_dispatch_run_queue(Manager *m);
unsigned manager_dispatch_dbus_queue(Manager *m);

int manager_loop(Manager *m);

const char *manager_running_as_to_string(ManagerRunningAs i);
ManagerRunningAs manager_running_as_from_string(const char *s);

#endif
