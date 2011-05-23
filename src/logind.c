/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <pwd.h>
#include <libudev.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "logind.h"
#include "dbus-common.h"
#include "dbus-loop.h"

enum {
        FD_UDEV,
        FD_CONSOLE,
        FD_BUS
};

Manager *manager_new(void) {
        Manager *m;

        m = new0(Manager, 1);
        if (!m)
                return NULL;

        m->console_active_fd = -1;
        m->bus_fd = -1;
        m->udev_fd = -1;
        m->epoll_fd = -1;
        m->n_autovts = 6;

        m->devices = hashmap_new(string_hash_func, string_compare_func);
        m->seats = hashmap_new(string_hash_func, string_compare_func);
        m->sessions = hashmap_new(string_hash_func, string_compare_func);
        m->users = hashmap_new(trivial_hash_func, trivial_compare_func);

        if (!m->devices || !m->seats || !m->sessions || !m->users) {
                manager_free(m);
                return NULL;
        }

        m->udev = udev_new();
        if (!m->udev) {
                manager_free(m);
                return NULL;
        }

        if (cg_get_user_path(&m->cgroup_path) < 0) {
                manager_free(m);
                return NULL;
        }

        return m;
}

void manager_free(Manager *m) {
        Session *session;
        User *u;
        Device *d;
        Seat *s;

        assert(m);

        while ((session = hashmap_first(m->sessions)))
                session_free(session);

        while ((u = hashmap_first(m->users)))
                user_free(u);

        while ((d = hashmap_first(m->devices)))
                device_free(d);

        while ((s = hashmap_first(m->seats)))
                seat_free(s);

        hashmap_free(m->sessions);
        hashmap_free(m->users);
        hashmap_free(m->devices);
        hashmap_free(m->seats);

        if (m->console_active_fd >= 0)
                close_nointr_nofail(m->console_active_fd);

        if (m->udev_monitor)
                udev_monitor_unref(m->udev_monitor);

        if (m->udev)
                udev_unref(m->udev);

        if (m->bus) {
                dbus_connection_flush(m->bus);
                dbus_connection_close(m->bus);
                dbus_connection_unref(m->bus);
        }

        if (m->bus_fd >= 0)
                close_nointr_nofail(m->bus_fd);

        if (m->epoll_fd >= 0)
                close_nointr_nofail(m->epoll_fd);

        free(m->cgroup_path);
        free(m);
}

int manager_add_device(Manager *m, const char *sysfs, Device **_device) {
        Device *d;

        assert(m);
        assert(sysfs);

        d = hashmap_get(m->devices, sysfs);
        if (d) {
                if (_device)
                        *_device = d;

                return 0;
        }

        d = device_new(m, sysfs);
        if (!d)
                return -ENOMEM;

        if (_device)
                *_device = d;

        return 0;
}

int manager_add_seat(Manager *m, const char *id, Seat **_seat) {
        Seat *s;

        assert(m);
        assert(id);

        s = hashmap_get(m->seats, id);
        if (s) {
                if (_seat)
                        *_seat = s;

                return 0;
        }

        s = seat_new(m, id);
        if (!s)
                return -ENOMEM;

        if (_seat)
                *_seat = s;

        return 0;
}

int manager_add_session(Manager *m, User *u, const char *id, Session **_session) {
        Session *s;

        assert(m);
        assert(id);

        s = hashmap_get(m->sessions, id);
        if (s) {
                if (_session)
                        *_session = s;

                return 0;
        }

        s = session_new(m, u, id);
        if (!s)
                return -ENOMEM;

        if (_session)
                *_session = s;

        return 0;
}

int manager_add_user(Manager *m, uid_t uid, gid_t gid, const char *name, User **_user) {
        User *u;
        int r;

        assert(m);
        assert(name);

        u = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
        if (u) {
                if (_user)
                        *_user = u;

                return 0;
        }

        u = user_new(m, uid, gid, name);
        if (!u)
                return -ENOMEM;

        r = user_start(u);
        if (r < 0) {
                user_stop(u);
                user_free(u);
        } else {
                if (_user)
                        *_user = u;
        }

        return r;
}

int manager_add_user_by_name(Manager *m, const char *name, User **_user) {
        struct passwd *p;

        assert(m);
        assert(name);

        errno = 0;
        p = getpwnam(name);
        if (!p)
                return errno ? -errno : -ENOENT;

        return manager_add_user(m, p->pw_uid, p->pw_gid, name, _user);
}

int manager_add_user_by_uid(Manager *m, uid_t uid, User **_user) {
        struct passwd *p;

        assert(m);

        errno = 0;
        p = getpwuid(uid);
        if (!p)
                return errno ? -errno : -ENOENT;

        return manager_add_user(m, uid, p->pw_gid, p->pw_name, _user);
}

int manager_process_device(Manager *m, struct udev_device *d) {
        const char *sn;
        Seat *seat;
        Device *device;
        int r;

        assert(m);

        sn = udev_device_get_property_value(d, "SEAT");
        if (!sn)
                sn = "seat0";

        r = manager_add_device(m, udev_device_get_syspath(d), &device);
        if (r < 0)
                return r;

        r = manager_add_seat(m, sn, &seat);
        if (r < 0)
                return r;

        device_attach(device, seat);
        return 0;
}

int manager_enumerate_devices(Manager *m) {
        struct udev_list_entry *item = NULL, *first = NULL;
        struct udev_enumerate *e;
        int r = -ENOMEM;

        assert(m);

        /* Loads devices from udev and creates seats for them as
         * necessary */

        e = udev_enumerate_new(m->udev);
        if (!e)
                return -ENOMEM;

        if (udev_enumerate_add_match_subsystem(e, "graphics") < 0)
                goto finish;

        if (udev_enumerate_add_match_tag(e, "seat") < 0)
                goto finish;

        if (udev_enumerate_scan_devices(e) < 0)
                goto finish;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                int k;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d)
                        goto finish;

                k = manager_process_device(m, d);
                udev_device_unref(d);

                if (k < 0)
                        r = k;
        }

finish:
        if (e)
                udev_enumerate_unref(e);

        return r;
}

int manager_enumerate_seats(Manager *m) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        assert(m);

        /* This loads data about seats stored on disk, but does not
         * actually create any seats. Removes data of seats that no
         * longer exist. */

        d = opendir("/run/systemd/seats");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/seats: %m");
                return -errno;
        }

        while ((de = readdir(d))) {
                Seat *s;
                int k;

                if (!dirent_is_file(de))
                        continue;

                s = hashmap_get(m->seats, de->d_name);
                if (!s) {
                        unlinkat(dirfd(d), de->d_name, 0);
                        continue;
                }

                k = seat_load(s);
                if (k < 0)
                        r = k;
        }

        closedir(d);

        return r;
}

static int manager_enumerate_users_from_cgroup(Manager *m) {
        int r = 0;
        char *name;
        DIR *d;

        r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_path, &d);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                log_error("Failed to open %s: %s", m->cgroup_path, strerror(-r));
                return r;
        }

        while ((r = cg_read_subgroup(d, &name)) > 0) {
                User *user;

                r = manager_add_user_by_name(m, name, &user);
                free(name);

                if (r < 0)
                        break;

                if (user->cgroup_path)
                        continue;

                if (asprintf(&user->cgroup_path, "%s/%s", m->cgroup_path, name) < 0) {
                        r = -ENOMEM;
                        break;
                }
        }

        if (d)
                closedir(d);

        return r;
}

int manager_enumerate_users(Manager *m) {
        DIR *d;
        struct dirent *de;
        int r;

        assert(m);

        r = manager_enumerate_users_from_cgroup(m);

        d = opendir("/run/systemd/users");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/users: %m");
                return -errno;
        }

        while ((de = readdir(d))) {
                unsigned long ul;
                User *u;
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = safe_atolu(de->d_name, &ul);
                if (k < 0) {
                        log_error("Failed to parse file name %s: %s", de->d_name, strerror(-k));
                        continue;
                }

                u = hashmap_get(m->users, ULONG_TO_PTR(ul));
                if (!u) {
                        unlinkat(dirfd(d), de->d_name, 0);
                        continue;
                }

                k = user_load(u);
                if (k < 0)
                        r = k;
        }

        closedir(d);

        return r;
}

static int manager_enumerate_sessions_from_cgroup(Manager *m) {
        User *u;
        Iterator i;
        int r = 0;

        HASHMAP_FOREACH(u, m->users, i) {
                DIR *d;
                char *name;
                int k;

                k = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, &d);
                if (k < 0) {
                        if (k == -ENOENT)
                                continue;

                        log_error("Failed to open %s: %s", u->cgroup_path, strerror(-k));
                        r = k;
                        continue;
                }

                while ((k = cg_read_subgroup(d, &name)) > 0) {
                        Session *session;

                        k = manager_add_session(m, u, name, &session);
                        free(name);

                        if (k < 0)
                                break;

                        if (session->cgroup_path)
                                continue;

                        if (asprintf(&session->cgroup_path, "%s/%s", u->cgroup_path, name) < 0) {
                                k = -ENOMEM;
                                break;
                        }
                }

                closedir(d);

                if (k < 0)
                        r = k;
        }

        return r;
}

int manager_enumerate_sessions(Manager *m) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        assert(m);

        r = manager_enumerate_sessions_from_cgroup(m);

        d = opendir("/run/systemd/sessions");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/sessions: %m");
                return -errno;
        }

        while ((de = readdir(d))) {
                struct Session *s;
                int k;

                if (!dirent_is_file(de))
                        continue;

                s = hashmap_get(m->sessions, de->d_name);
                if (!s) {
                        unlinkat(dirfd(d), de->d_name, 0);
                        continue;
                }

                k = session_load(s);
                if (k < 0)
                        r = k;
        }

        closedir(d);

        return r;
}

int manager_start_linger_users(Manager *m) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        d = opendir("/var/lib/systemd/linger");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /var/lib/systemd/linger/: %m");
                return -errno;
        }

        while ((de = readdir(d))) {
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_user_by_name(m, de->d_name, NULL);
                if (k < 0) {
                        log_notice("Couldn't add lingering user %s: %s", de->d_name, strerror(-k));
                        r = k;
                }
        }

        closedir(d);

        return r;
}

int manager_dispatch_udev(Manager *m) {
        struct udev_device *d;
        int r;

        assert(m);

        d = udev_monitor_receive_device(m->udev_monitor);
        if (!d)
                return -ENOMEM;

        r = manager_process_device(m, d);
        udev_device_unref(d);

        return r;
}

int manager_dispatch_console(Manager *m) {
        char t[64];
        ssize_t k;
        int r, vtnr;

        assert(m);

        lseek(m->console_active_fd, SEEK_SET, 0);

        k = read(m->console_active_fd, t, sizeof(t)-1);
        if (k <= 0) {
                log_error("Failed to read current console: %s", k < 0 ? strerror(-errno) : "EOF");
                return k < 0 ? -errno : -EIO;
        }

        t[k] = 0;
        if (!startswith(t, "tty")) {
                log_error("Hm, /sys/class/tty/tty0/active is badly formatted.");
                return -EIO;
        }

        r = safe_atoi(t+3, &vtnr);
        if (r < 0) {
                log_error("Failed to parse VT number %s", t+3);
                return r;
        }

        if (vtnr <= 0) {
                log_error("VT number invalid: %s", t+3);
                return -EIO;
        }

        if (m->vtconsole)
                seat_active_vt_changed(m->vtconsole, vtnr);

        return 0;
}

int manager_spawn_autovt(Manager *m, int vtnr) {
        assert(m);

        return 0;
}

static DBusHandlerResult login_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult login_message_filter(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        return DBUS_HANDLER_RESULT_HANDLED;
}

static int manager_connect_bus(Manager *m) {
        const DBusObjectPathVTable login_vtable = {
                .message_function = login_message_handler
        };

        DBusError error;
        int r;
        struct epoll_event ev;

        assert(m);
        assert(!m->bus);
        assert(m->bus_fd < 0);

        dbus_error_init(&error);

        m->bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!m->bus) {
                log_error("Failed to get system D-Bus connection: %s", error.message);
                r = -ECONNREFUSED;
                goto fail;
        }

        if (!dbus_connection_register_object_path(m->bus, "/org/freedesktop/login1", &login_vtable, NULL)) {
                log_error("Not enough memory");
                r = -ENOMEM;
                goto fail;
        }

        if (!dbus_connection_add_filter(m->bus, login_message_filter, m, NULL)) {
                log_error("Not enough memory");
                r = -ENOMEM;
                goto fail;
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "interface='org.freedesktop.systemd1.Agent',"
                           "member='Released',"
                           "path='/org/freedesktop/systemd1/agent'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to register match: %s", error.message);
                r = -EIO;
                goto fail;
        }

        if (dbus_bus_request_name(m->bus, "org.freedesktop.login1", DBUS_NAME_FLAG_DO_NOT_QUEUE, &error) < 0) {
                log_error("Failed to register name on bus: %s", error.message);
                r = -EEXIST;
                goto fail;
        }

        m->bus_fd = bus_loop_open(m->bus);
        if (m->bus_fd < 0) {
                r = m->bus_fd;
                goto fail;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.u32 = FD_BUS;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->bus_fd, &ev) < 0)
                goto fail;

        return 0;

fail:
        dbus_error_free(&error);

        return r;
}

static int manager_connect_console(Manager *m) {
        struct epoll_event ev;

        assert(m);
        assert(m->console_active_fd < 0);

        m->console_active_fd = open("/sys/class/tty/tty0/active", O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (m->console_active_fd < 0) {
                log_error("Failed to open /sys/class/tty/tty0/active: %m");
                return -errno;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.u32 = FD_CONSOLE;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->console_active_fd, &ev) < 0)
                return -errno;

        return 0;
}

static int manager_connect_udev(Manager *m) {
        struct epoll_event ev;

        assert(m);
        assert(!m->udev_monitor);

        m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
        if (!m->udev_monitor)
                return -ENOMEM;

        udev_monitor_filter_add_match_tag(m->udev_monitor, "seat");

        if (udev_monitor_filter_add_match_subsystem_devtype(m->udev_monitor, "graphics", NULL) < 0)
                return -ENOMEM;

        if (udev_monitor_enable_receiving(m->udev_monitor) < 0)
                return -ENOMEM;

        m->udev_fd = udev_monitor_get_fd(m->udev_monitor);

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.u32 = FD_UDEV;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->udev_fd, &ev) < 0)
                return -errno;

        return 0;
}

int manager_startup(Manager *m) {
        int r;

        assert(m);
        assert(m->epoll_fd <= 0);

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0)
                return -errno;

        /* Connect to udev */
        r = manager_connect_udev(m);
        if (r < 0)
                return r;

        /* Connect to console */
        r = manager_connect_console(m);
        if (r < 0)
                return r;

        /* Connect to the bus */
        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        /* Deserialize state */
        manager_enumerate_devices(m);
        manager_enumerate_seats(m);
        manager_enumerate_users(m);
        manager_enumerate_sessions(m);

        /* Spawn lingering users */
        manager_start_linger_users(m);

        return 0;
}

int manager_run(Manager *m) {
        assert(m);

        for (;;) {
                struct epoll_event event;
                int n;

                if (dbus_connection_dispatch(m->bus) != DBUS_DISPATCH_COMPLETE)
                        continue;

                n = epoll_wait(m->epoll_fd, &event, 1, -1);
                if (n < 0) {
                        log_error("epoll() failed: %m");
                        return -errno;
                }

                switch (event.data.u32) {

                case FD_UDEV:
                        manager_dispatch_udev(m);
                        break;

                case FD_CONSOLE:
                        manager_dispatch_console(m);
                        break;

                case FD_BUS:
                        bus_loop_dispatch(m->bus_fd);
                        break;
                }
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        int r = 0;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        umask(0022);

        m = manager_new();
        if (!m) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        r = manager_startup(m);
        if (r < 0) {
                log_error("Failed to fully start up daemon: %s", strerror(-r));
                goto finish;
        }

        r = manager_run(m);

finish:
        if (m)
                manager_free(m);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
