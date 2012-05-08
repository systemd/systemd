/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foologindhfoo
#define foologindhfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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
#include <dbus/dbus.h>
#include <libudev.h>

#include "util.h"
#include "audit.h"
#include "list.h"
#include "hashmap.h"
#include "cgroup-util.h"

typedef struct Manager Manager;

#include "logind-device.h"
#include "logind-seat.h"
#include "logind-session.h"
#include "logind-user.h"
#include "logind-inhibit.h"

struct Manager {
        DBusConnection *bus;

        Hashmap *devices;
        Hashmap *seats;
        Hashmap *sessions;
        Hashmap *users;
        Hashmap *inhibitors;

        LIST_HEAD(Seat, seat_gc_queue);
        LIST_HEAD(Session, session_gc_queue);
        LIST_HEAD(User, user_gc_queue);

        struct udev *udev;
        struct udev_monitor *udev_seat_monitor, *udev_vcsa_monitor;

        int udev_seat_fd;
        int udev_vcsa_fd;

        int console_active_fd;
        int bus_fd;
        int epoll_fd;

        unsigned n_autovts;

        Seat *vtconsole;

        char *cgroup_path;
        char **controllers, **reset_controllers;

        char **kill_only_users, **kill_exclude_users;

        bool kill_user_processes;

        unsigned long session_counter;
        unsigned long inhibit_counter;

        Hashmap *cgroups;
        Hashmap *session_fds;
        Hashmap *inhibitor_fds;

        /* If a shutdown was delayed due to a inhibitor this contains
           the unit name we are supposed to start after the delay is
           over */
        const char *delayed_unit;
        InhibitWhat delayed_what;
        usec_t delayed_timestamp;

        usec_t inhibit_delay_max;
};

enum {
        FD_SEAT_UDEV,
        FD_VCSA_UDEV,
        FD_CONSOLE,
        FD_BUS,
        FD_FIFO_BASE
};

Manager *manager_new(void);
void manager_free(Manager *m);

int manager_add_device(Manager *m, const char *sysfs, Device **_device);
int manager_add_seat(Manager *m, const char *id, Seat **_seat);
int manager_add_session(Manager *m, User *u, const char *id, Session **_session);
int manager_add_user(Manager *m, uid_t uid, gid_t gid, const char *name, User **_user);
int manager_add_user_by_name(Manager *m, const char *name, User **_user);
int manager_add_user_by_uid(Manager *m, uid_t uid, User **_user);
int manager_add_inhibitor(Manager *m, const char* id, Inhibitor **_inhibitor);

int manager_process_seat_device(Manager *m, struct udev_device *d);
int manager_dispatch_seat_udev(Manager *m);
int manager_dispatch_vcsa_udev(Manager *m);
int manager_dispatch_console(Manager *m);

int manager_enumerate_devices(Manager *m);
int manager_enumerate_seats(Manager *m);
int manager_enumerate_sessions(Manager *m);
int manager_enumerate_users(Manager *m);
int manager_enumerate_inhibitors(Manager *m);

int manager_startup(Manager *m);
int manager_run(Manager *m);
int manager_spawn_autovt(Manager *m, int vtnr);

void manager_cgroup_notify_empty(Manager *m, const char *cgroup);

void manager_gc(Manager *m, bool drop_not_started);

int manager_get_idle_hint(Manager *m, dual_timestamp *t);

int manager_get_session_by_cgroup(Manager *m, const char *cgroup, Session **session);
int manager_get_session_by_pid(Manager *m, pid_t pid, Session **session);

extern const DBusObjectPathVTable bus_manager_vtable;

DBusHandlerResult bus_message_filter(DBusConnection *c, DBusMessage *message, void *userdata);

int manager_send_changed(Manager *manager, const char *properties);

int manager_dispatch_delayed(Manager *manager);

/* gperf lookup function */
const struct ConfigPerfItem* logind_gperf_lookup(const char *key, unsigned length);

#endif
