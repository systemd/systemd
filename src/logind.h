/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foologindhfoo
#define foologindhfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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
#include <dbus/dbus.h>
#include <libudev.h>

#include "util.h"
#include "list.h"
#include "hashmap.h"
#include "cgroup-util.h"

/* TODO:
 *
 * recreate VTs when disallocated
 * udev rules
 * spawn user systemd
 * non-local X11 server
 * udev-acl
 * reboot/shutdown halt management
 * PAM rewrite
 */

typedef struct Manager Manager;
typedef struct Device Device;
typedef struct Seat Seat;
typedef struct Session Session;
typedef struct User User;

struct Device {
        Manager *manager;

        char *sysfs;
        Seat *seat;

        dual_timestamp timestamp;

        LIST_FIELDS(struct Device, devices);
};

struct Seat {
        Manager *manager;
        char *id;

        char *state_file;

        LIST_HEAD(Device, devices);

        Session *active;
        LIST_HEAD(Session, sessions);
};

typedef enum SessionType {
        SESSION_TERMINAL,
        SESSION_X11,
        _SESSION_TYPE_MAX,
        _SESSION_TYPE_INVALID = -1
} SessionType;

struct Session {
        Manager *manager;

        char *id;
        SessionType type;

        char *state_file;

        User *user;

        dual_timestamp timestamp;

        char *tty;
        char *display;

        bool remote;
        char *remote_host;

        int vtnr;
        Seat *seat;

        pid_t leader;
        uint64_t audit_id;

        int pipe_fd;

        char *cgroup_path;
        char **controllers, **reset_controllers;

        bool kill_processes;

        LIST_FIELDS(Session, sessions_by_user);
        LIST_FIELDS(Session, sessions_by_seat);
};

typedef enum UserState {
        USER_OFFLINE,
        USER_LINGERING,
        USER_ONLINE,
        USER_ACTIVE,
        _USER_STATE_MAX,
        _USER_STATE_INVALID = -1
} UserState;

struct User {
        Manager *manager;

        uid_t uid;
        gid_t gid;
        char *name;

        char *state_file;
        char *runtime_path;
        char *service;
        char *cgroup_path;

        Session *display;

        dual_timestamp timestamp;

        LIST_HEAD(Session, sessions);
};

struct Manager {
        DBusConnection *bus;

        Hashmap *devices;
        Hashmap *seats;
        Hashmap *sessions;
        Hashmap *users;

        struct udev *udev;
        struct udev_monitor *udev_monitor;

        int udev_fd;
        int console_active_fd;
        int bus_fd;
        int epoll_fd;

        int n_autovts;

        Seat *vtconsole;

        char *cgroup_path;
        char **controllers, **reset_controllers;

        char **kill_only_users, **kill_exlude_users;

        bool kill_user_processes;
};

Device* device_new(Manager *m, const char *sysfs);
void device_free(Device *d);
void device_attach(Device *d, Seat *s);
void device_detach(Device *d);

Seat *seat_new(Manager *m, const char *id);
void seat_free(Seat *s);
int seat_preallocate_vts(Seat *s);
void seat_active_vt_changed(Seat *s, int vtnr);
int seat_apply_acls(Seat *s);
int seat_stop(Seat *s);
int seat_save(Seat *s);
int seat_load(Seat *s);

Session *session_new(Manager *m, User *u, const char *id);
void session_free(Session *s);
int session_activate(Session *s);
bool session_is_active(Session *s);
int session_check_gc(Session *s);
int session_start(Session *s);
int session_stop(Session *s);
int session_save(Session *s);
int session_load(Session *s);

User* user_new(Manager *m, uid_t uid, gid_t gid, const char *name);
void user_free(User *u);
int user_start(User *u);
int user_stop(User *u);
int user_check_gc(User *u);
UserState user_get_state(User *u);
int user_save(User *u);
int user_load(User *u);

Manager *manager_new(void);
void manager_free(Manager *m);
int manager_add_device(Manager *m, const char *sysfs, Device **_device);
int manager_add_seat(Manager *m, const char *id, Seat **_seat);
int manager_add_session(Manager *m, User *u, const char *id, Session **_session);
int manager_add_user(Manager *m, uid_t uid, gid_t gid, const char *name, User **_user);
int manager_add_user_by_name(Manager *m, const char *name, User **_user);
int manager_add_user_by_uid(Manager *m, uid_t uid, User **_user);
int manager_process_device(Manager *m, struct udev_device *d);
int manager_dispatch_udev(Manager *m);
int manager_dispatch_console(Manager *m);
int manager_enumerate_devices(Manager *m);
int manager_enumerate_seats(Manager *m);
int manager_enumerate_sessions(Manager *m);
int manager_enumerate_users(Manager *m);
int manager_start_one_linger_user(Manager *m, const char *user);
int manager_start_linger_users(Manager *m);
int manager_startup(Manager *m);
int manager_run(Manager *m);
int manager_spawn_autovt(Manager *m, int vtnr);

const char* session_type_to_string(SessionType t);
SessionType session_type_from_string(const char *s);

const char* user_state_to_string(UserState s);
UserState user_state_from_string(const char *s);

bool x11_display_is_local(const char *display);

#endif
