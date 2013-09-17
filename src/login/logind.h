/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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
#include "logind-button.h"
#include "logind-action.h"

struct Manager {
        DBusConnection *bus;

        Hashmap *devices;
        Hashmap *seats;
        Hashmap *sessions;
        Hashmap *users;
        Hashmap *inhibitors;
        Hashmap *buttons;
        Hashmap *busnames;

        LIST_HEAD(Seat, seat_gc_queue);
        LIST_HEAD(Session, session_gc_queue);
        LIST_HEAD(User, user_gc_queue);

        struct udev *udev;
        struct udev_monitor *udev_seat_monitor, *udev_device_monitor, *udev_vcsa_monitor, *udev_button_monitor;

        int udev_seat_fd;
        int udev_device_fd;
        int udev_vcsa_fd;
        int udev_button_fd;

        int console_active_fd;
        int bus_fd;
        int epoll_fd;

        unsigned n_autovts;

        unsigned reserve_vt;
        int reserve_vt_fd;

        Seat *seat0;

        char **kill_only_users, **kill_exclude_users;
        bool kill_user_processes;

        unsigned long session_counter;
        unsigned long inhibit_counter;

        Hashmap *session_units;
        Hashmap *user_units;

        Hashmap *session_fds;
        Hashmap *inhibitor_fds;
        Hashmap *button_fds;

        usec_t inhibit_delay_max;

        /* If an action is currently being executed or is delayed,
         * this is != 0 and encodes what is being done */
        InhibitWhat action_what;

        /* If a shutdown/suspend was delayed due to a inhibitor this
           contains the unit name we are supposed to start after the
           delay is over */
        const char *action_unit;

        /* If a shutdown/suspend is currently executed, then this is
         * the job of it */
        char *action_job;
        usec_t action_timestamp;

        int idle_action_fd; /* the timer_fd */
        usec_t idle_action_usec;
        usec_t idle_action_not_before_usec;
        HandleAction idle_action;

        HandleAction handle_power_key;
        HandleAction handle_suspend_key;
        HandleAction handle_hibernate_key;
        HandleAction handle_lid_switch;

        bool power_key_ignore_inhibited;
        bool suspend_key_ignore_inhibited;
        bool hibernate_key_ignore_inhibited;
        bool lid_switch_ignore_inhibited;
};

enum {
        FD_SEAT_UDEV,
        FD_DEVICE_UDEV,
        FD_VCSA_UDEV,
        FD_BUTTON_UDEV,
        FD_CONSOLE,
        FD_BUS,
        FD_IDLE_ACTION,
        FD_OTHER_BASE
};

Manager *manager_new(void);
void manager_free(Manager *m);

int manager_add_device(Manager *m, const char *sysfs, bool master, Device **_device);
int manager_add_button(Manager *m, const char *name, Button **_button);
int manager_add_seat(Manager *m, const char *id, Seat **_seat);
int manager_add_session(Manager *m, const char *id, Session **_session);
int manager_add_user(Manager *m, uid_t uid, gid_t gid, const char *name, User **_user);
int manager_add_user_by_name(Manager *m, const char *name, User **_user);
int manager_add_user_by_uid(Manager *m, uid_t uid, User **_user);
int manager_add_inhibitor(Manager *m, const char* id, Inhibitor **_inhibitor);

int manager_process_seat_device(Manager *m, struct udev_device *d);
int manager_process_button_device(Manager *m, struct udev_device *d);

int manager_dispatch_seat_udev(Manager *m);
int manager_dispatch_vcsa_udev(Manager *m);
int manager_dispatch_button_udev(Manager *m);
int manager_dispatch_console(Manager *m);
int manager_dispatch_idle_action(Manager *m);

int manager_enumerate_devices(Manager *m);
int manager_enumerate_buttons(Manager *m);
int manager_enumerate_seats(Manager *m);
int manager_enumerate_sessions(Manager *m);
int manager_enumerate_users(Manager *m);
int manager_enumerate_inhibitors(Manager *m);

int manager_startup(Manager *m);
int manager_run(Manager *m);
int manager_spawn_autovt(Manager *m, int vtnr);

void manager_gc(Manager *m, bool drop_not_started);

bool manager_shall_kill(Manager *m, const char *user);

int manager_get_idle_hint(Manager *m, dual_timestamp *t);

int manager_get_user_by_pid(Manager *m, pid_t pid, User **user);
int manager_get_session_by_pid(Manager *m, pid_t pid, Session **session);

extern const DBusObjectPathVTable bus_manager_vtable;

DBusHandlerResult bus_message_filter(DBusConnection *c, DBusMessage *message, void *userdata);

int bus_manager_shutdown_or_sleep_now_or_later(Manager *m, const char *unit_name, InhibitWhat w, DBusError *error);

int manager_send_changed(Manager *manager, const char *properties);

int manager_dispatch_delayed(Manager *manager);

int manager_start_scope(Manager *manager, const char *scope, pid_t pid, const char *slice, const char *description, const char *after, const char *kill_mode, DBusError *error, char **job);
int manager_start_unit(Manager *manager, const char *unit, DBusError *error, char **job);
int manager_stop_unit(Manager *manager, const char *unit, DBusError *error, char **job);
int manager_kill_unit(Manager *manager, const char *unit, KillWho who, int signo, DBusError *error);
int manager_unit_is_active(Manager *manager, const char *unit);

/* gperf lookup function */
const struct ConfigPerfItem* logind_gperf_lookup(const char *key, unsigned length);

int manager_watch_busname(Manager *manager, const char *name);
void manager_drop_busname(Manager *manager, const char *name);
