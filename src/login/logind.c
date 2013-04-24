/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <pwd.h>
#include <libudev.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <linux/vt.h>
#include <sys/timerfd.h>

#include <systemd/sd-daemon.h>

#include "logind.h"
#include "dbus-common.h"
#include "dbus-loop.h"
#include "strv.h"
#include "conf-parser.h"
#include "mkdir.h"

Manager *manager_new(void) {
        Manager *m;

        m = new0(Manager, 1);
        if (!m)
                return NULL;

        m->console_active_fd = -1;
        m->bus_fd = -1;
        m->udev_seat_fd = -1;
        m->udev_vcsa_fd = -1;
        m->udev_button_fd = -1;
        m->epoll_fd = -1;
        m->reserve_vt_fd = -1;

        m->n_autovts = 6;
        m->reserve_vt = 6;
        m->inhibit_delay_max = 5 * USEC_PER_SEC;
        m->handle_power_key = HANDLE_POWEROFF;
        m->handle_suspend_key = HANDLE_SUSPEND;
        m->handle_hibernate_key = HANDLE_HIBERNATE;
        m->handle_lid_switch = HANDLE_SUSPEND;
        m->lid_switch_ignore_inhibited = true;

        m->idle_action_fd = -1;
        m->idle_action_usec = 30 * USEC_PER_MINUTE;
        m->idle_action = HANDLE_IGNORE;
        m->idle_action_not_before_usec = now(CLOCK_MONOTONIC);

        m->devices = hashmap_new(string_hash_func, string_compare_func);
        m->seats = hashmap_new(string_hash_func, string_compare_func);
        m->sessions = hashmap_new(string_hash_func, string_compare_func);
        m->users = hashmap_new(trivial_hash_func, trivial_compare_func);
        m->inhibitors = hashmap_new(string_hash_func, string_compare_func);
        m->buttons = hashmap_new(string_hash_func, string_compare_func);

        m->user_cgroups = hashmap_new(string_hash_func, string_compare_func);
        m->session_cgroups = hashmap_new(string_hash_func, string_compare_func);

        m->session_fds = hashmap_new(trivial_hash_func, trivial_compare_func);
        m->inhibitor_fds = hashmap_new(trivial_hash_func, trivial_compare_func);
        m->button_fds = hashmap_new(trivial_hash_func, trivial_compare_func);

        if (!m->devices || !m->seats || !m->sessions || !m->users || !m->inhibitors || !m->buttons ||
            !m->user_cgroups || !m->session_cgroups ||
            !m->session_fds || !m->inhibitor_fds || !m->button_fds) {
                manager_free(m);
                return NULL;
        }

        m->reset_controllers = strv_new("cpu", NULL);
        m->kill_exclude_users = strv_new("root", NULL);
        if (!m->reset_controllers || !m->kill_exclude_users) {
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
        Inhibitor *i;
        Button *b;

        assert(m);

        while ((session = hashmap_first(m->sessions)))
                session_free(session);

        while ((u = hashmap_first(m->users)))
                user_free(u);

        while ((d = hashmap_first(m->devices)))
                device_free(d);

        while ((s = hashmap_first(m->seats)))
                seat_free(s);

        while ((i = hashmap_first(m->inhibitors)))
                inhibitor_free(i);

        while ((b = hashmap_first(m->buttons)))
                button_free(b);

        hashmap_free(m->devices);
        hashmap_free(m->seats);
        hashmap_free(m->sessions);
        hashmap_free(m->users);
        hashmap_free(m->inhibitors);
        hashmap_free(m->buttons);

        hashmap_free(m->user_cgroups);
        hashmap_free(m->session_cgroups);

        hashmap_free(m->session_fds);
        hashmap_free(m->inhibitor_fds);
        hashmap_free(m->button_fds);

        if (m->console_active_fd >= 0)
                close_nointr_nofail(m->console_active_fd);

        if (m->udev_seat_monitor)
                udev_monitor_unref(m->udev_seat_monitor);
        if (m->udev_vcsa_monitor)
                udev_monitor_unref(m->udev_vcsa_monitor);
        if (m->udev_button_monitor)
                udev_monitor_unref(m->udev_button_monitor);

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

        if (m->reserve_vt_fd >= 0)
                close_nointr_nofail(m->reserve_vt_fd);

        if (m->idle_action_fd >= 0)
                close_nointr_nofail(m->idle_action_fd);

        strv_free(m->controllers);
        strv_free(m->reset_controllers);
        strv_free(m->kill_only_users);
        strv_free(m->kill_exclude_users);

        free(m->action_job);

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

        if (_user)
                *_user = u;

        return 0;
}

int manager_add_user_by_name(Manager *m, const char *name, User **_user) {
        uid_t uid;
        gid_t gid;
        int r;

        assert(m);
        assert(name);

        r = get_user_creds(&name, &uid, &gid, NULL, NULL);
        if (r < 0)
                return r;

        return manager_add_user(m, uid, gid, name, _user);
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

int manager_add_inhibitor(Manager *m, const char* id, Inhibitor **_inhibitor) {
        Inhibitor *i;

        assert(m);
        assert(id);

        i = hashmap_get(m->inhibitors, id);
        if (i) {
                if (_inhibitor)
                        *_inhibitor = i;

                return 0;
        }

        i = inhibitor_new(m, id);
        if (!i)
                return -ENOMEM;

        if (_inhibitor)
                *_inhibitor = i;

        return 0;
}

int manager_add_button(Manager *m, const char *name, Button **_button) {
        Button *b;

        assert(m);
        assert(name);

        b = hashmap_get(m->buttons, name);
        if (b) {
                if (_button)
                        *_button = b;

                return 0;
        }

        b = button_new(m, name);
        if (!b)
                return -ENOMEM;

        if (_button)
                *_button = b;

        return 0;
}

int manager_process_seat_device(Manager *m, struct udev_device *d) {
        Device *device;
        int r;

        assert(m);

        if (streq_ptr(udev_device_get_action(d), "remove")) {

                device = hashmap_get(m->devices, udev_device_get_syspath(d));
                if (!device)
                        return 0;

                seat_add_to_gc_queue(device->seat);
                device_free(device);

        } else {
                const char *sn;
                Seat *seat;

                sn = udev_device_get_property_value(d, "ID_SEAT");
                if (isempty(sn))
                        sn = "seat0";

                if (!seat_name_is_valid(sn)) {
                        log_warning("Device with invalid seat name %s found, ignoring.", sn);
                        return 0;
                }

                r = manager_add_device(m, udev_device_get_syspath(d), &device);
                if (r < 0)
                        return r;

                r = manager_add_seat(m, sn, &seat);
                if (r < 0) {
                        if (!device->seat)
                                device_free(device);

                        return r;
                }

                device_attach(device, seat);
                seat_start(seat);
        }

        return 0;
}

int manager_process_button_device(Manager *m, struct udev_device *d) {
        Button *b;

        int r;

        assert(m);

        if (streq_ptr(udev_device_get_action(d), "remove")) {

                b = hashmap_get(m->buttons, udev_device_get_sysname(d));
                if (!b)
                        return 0;

                button_free(b);

        } else {
                const char *sn;

                r = manager_add_button(m, udev_device_get_sysname(d), &b);
                if (r < 0)
                        return r;

                sn = udev_device_get_property_value(d, "ID_SEAT");
                if (isempty(sn))
                        sn = "seat0";

                button_set_seat(b, sn);
                button_open(b);
        }

        return 0;
}

int manager_enumerate_devices(Manager *m) {
        struct udev_list_entry *item = NULL, *first = NULL;
        struct udev_enumerate *e;
        int r;

        assert(m);

        /* Loads devices from udev and creates seats for them as
         * necessary */

        e = udev_enumerate_new(m->udev);
        if (!e) {
                r = -ENOMEM;
                goto finish;
        }

        r = udev_enumerate_add_match_tag(e, "master-of-seat");
        if (r < 0)
                goto finish;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                goto finish;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                int k;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                k = manager_process_seat_device(m, d);
                udev_device_unref(d);

                if (k < 0)
                        r = k;
        }

finish:
        if (e)
                udev_enumerate_unref(e);

        return r;
}

int manager_enumerate_buttons(Manager *m) {
        struct udev_list_entry *item = NULL, *first = NULL;
        struct udev_enumerate *e;
        int r;

        assert(m);

        /* Loads buttons from udev */

        if (m->handle_power_key == HANDLE_IGNORE &&
            m->handle_suspend_key == HANDLE_IGNORE &&
            m->handle_hibernate_key == HANDLE_IGNORE &&
            m->handle_lid_switch == HANDLE_IGNORE)
                return 0;

        e = udev_enumerate_new(m->udev);
        if (!e) {
                r = -ENOMEM;
                goto finish;
        }

        r = udev_enumerate_add_match_subsystem(e, "input");
        if (r < 0)
                goto finish;

        r = udev_enumerate_add_match_tag(e, "power-switch");
        if (r < 0)
                goto finish;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                goto finish;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                int k;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                k = manager_process_button_device(m, d);
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
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0, k;
        char *name;

        r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_path, &d);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                log_error("Failed to open %s: %s", m->cgroup_path, strerror(-r));
                return r;
        }

        while ((k = cg_read_subgroup(d, &name)) > 0) {
                User *user;
                char *e;

                e = endswith(name, ".user");
                if (e) {
                        *e = 0;

                        k = manager_add_user_by_name(m, name, &user);
                        if (k < 0) {
                                free(name);
                                r = k;
                                continue;
                        }

                        user_add_to_gc_queue(user);

                        if (!user->cgroup_path) {
                                user->cgroup_path = strjoin(m->cgroup_path, "/", name, NULL);
                                if (!user->cgroup_path) {
                                        k = log_oom();
                                        free(name);
                                        break;
                                }
                        }
                }

                free(name);
        }

        if (k < 0)
                r = k;

        return r;
}

static int manager_enumerate_linger_users(Manager *m) {
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

int manager_enumerate_users(Manager *m) {
        DIR *d;
        struct dirent *de;
        int r, k;

        assert(m);

        /* First, enumerate user cgroups */
        r = manager_enumerate_users_from_cgroup(m);

        /* Second, add lingering users on top */
        k = manager_enumerate_linger_users(m);
        if (k < 0)
                r = k;

        /* Third, read in user data stored on disk */
        d = opendir("/run/systemd/users");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/users: %m");
                return -errno;
        }

        while ((de = readdir(d))) {
                uid_t uid;
                User *u;

                if (!dirent_is_file(de))
                        continue;

                k = parse_uid(de->d_name, &uid);
                if (k < 0) {
                        log_error("Failed to parse file name %s: %s", de->d_name, strerror(-k));
                        continue;
                }

                u = hashmap_get(m->users, ULONG_TO_PTR(uid));
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
                _cleanup_closedir_ DIR *d = NULL;
                char *name;
                int k;

                if (!u->cgroup_path)
                        continue;

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
                        char *e;

                        e = endswith(name, ".session");
                        if (e) {
                                *e = 0;

                                k = manager_add_session(m, u, name, &session);
                                if (k < 0) {
                                        free(name);
                                        r = k;
                                        continue;
                                }

                                session_add_to_gc_queue(session);

                                if (!session->cgroup_path) {
                                        session->cgroup_path = strjoin(m->cgroup_path, "/", name, NULL);
                                        if (!session->cgroup_path) {
                                                k = log_oom();
                                                free(name);
                                                break;
                                        }
                                }
                        }

                        free(name);
                }

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

        /* First enumerate session cgroups */
        r = manager_enumerate_sessions_from_cgroup(m);

        /* Second, read in session data stored on disk */
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

int manager_enumerate_inhibitors(Manager *m) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        assert(m);

        d = opendir("/run/systemd/inhibit");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/inhibit: %m");
                return -errno;
        }

        while ((de = readdir(d))) {
                int k;
                Inhibitor *i;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_inhibitor(m, de->d_name, &i);
                if (k < 0) {
                        log_notice("Couldn't add inhibitor %s: %s", de->d_name, strerror(-k));
                        r = k;
                        continue;
                }

                k = inhibitor_load(i);
                if (k < 0)
                        r = k;
        }

        closedir(d);

        return r;
}

int manager_dispatch_seat_udev(Manager *m) {
        struct udev_device *d;
        int r;

        assert(m);

        d = udev_monitor_receive_device(m->udev_seat_monitor);
        if (!d)
                return -ENOMEM;

        r = manager_process_seat_device(m, d);
        udev_device_unref(d);

        return r;
}

int manager_dispatch_vcsa_udev(Manager *m) {
        struct udev_device *d;
        int r = 0;
        const char *name;

        assert(m);

        d = udev_monitor_receive_device(m->udev_vcsa_monitor);
        if (!d)
                return -ENOMEM;

        name = udev_device_get_sysname(d);

        /* Whenever a VCSA device is removed try to reallocate our
         * VTs, to make sure our auto VTs never go away. */

        if (name && startswith(name, "vcsa") && streq_ptr(udev_device_get_action(d), "remove"))
                r = seat_preallocate_vts(m->vtconsole);

        udev_device_unref(d);

        return r;
}

int manager_dispatch_button_udev(Manager *m) {
        struct udev_device *d;
        int r;

        assert(m);

        d = udev_monitor_receive_device(m->udev_button_monitor);
        if (!d)
                return -ENOMEM;

        r = manager_process_button_device(m, d);
        udev_device_unref(d);

        return r;
}

int manager_dispatch_console(Manager *m) {
        assert(m);

        if (m->vtconsole)
                seat_read_active_vt(m->vtconsole);

        return 0;
}

static int vt_is_busy(int vtnr) {
        struct vt_stat vt_stat;
        int r = 0, fd;

        assert(vtnr >= 1);

        /* We explicitly open /dev/tty1 here instead of /dev/tty0. If
         * we'd open the latter we'd open the foreground tty which
         * hence would be unconditionally busy. By opening /dev/tty1
         * we avoid this. Since tty1 is special and needs to be an
         * explicitly loaded getty or DM this is safe. */

        fd = open_terminal("/dev/tty1", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, VT_GETSTATE, &vt_stat) < 0)
                r = -errno;
        else
                r = !!(vt_stat.v_state & (1 << vtnr));

        close_nointr_nofail(fd);

        return r;
}

int manager_spawn_autovt(Manager *m, int vtnr) {
        int r;
        char *name = NULL;
        const char *mode = "fail";

        assert(m);
        assert(vtnr >= 1);

        if ((unsigned) vtnr > m->n_autovts &&
            (unsigned) vtnr != m->reserve_vt)
                return 0;

        if ((unsigned) vtnr != m->reserve_vt) {
                /* If this is the reserved TTY, we'll start the getty
                 * on it in any case, but otherwise only if it is not
                 * busy. */

                r = vt_is_busy(vtnr);
                if (r < 0)
                        return r;
                else if (r > 0)
                        return -EBUSY;
        }

        if (asprintf(&name, "autovt@tty%i.service", vtnr) < 0) {
                log_error("Could not allocate service name.");
                r = -ENOMEM;
                goto finish;
        }

        r = bus_method_call_with_reply (
                        m->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING, &name,
                        DBUS_TYPE_STRING, &mode,
                        DBUS_TYPE_INVALID);

finish:
        free(name);

        return r;
}

static int manager_reserve_vt(Manager *m) {
        _cleanup_free_ char *p = NULL;

        assert(m);

        if (m->reserve_vt <= 0)
                return 0;

        if (asprintf(&p, "/dev/tty%u", m->reserve_vt) < 0)
                return log_oom();

        m->reserve_vt_fd = open(p, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (m->reserve_vt_fd < 0) {

                /* Don't complain on VT-less systems */
                if (errno != ENOENT)
                        log_warning("Failed to pin reserved VT: %m");
                return -errno;
        }

        return 0;
}

int manager_get_session_by_cgroup(Manager *m, const char *cgroup, Session **session) {
        Session *s;
        char *p;

        assert(m);
        assert(cgroup);
        assert(session);

        s = hashmap_get(m->session_cgroups, cgroup);
        if (s) {
                *session = s;
                return 1;
        }

        p = strdupa(cgroup);

        for (;;) {
                char *e;

                e = strrchr(p, '/');
                if (!e || e == p) {
                        *session = NULL;
                        return 0;
                }

                *e = 0;

                s = hashmap_get(m->session_cgroups, p);
                if (s) {
                        *session = s;
                        return 1;
                }
        }
}

int manager_get_user_by_cgroup(Manager *m, const char *cgroup, User **user) {
        User *u;
        char *p;

        assert(m);
        assert(cgroup);
        assert(user);

        u = hashmap_get(m->user_cgroups, cgroup);
        if (u) {
                *user = u;
                return 1;
        }

        p = strdupa(cgroup);
        if (!p)
                return log_oom();

        for (;;) {
                char *e;

                e = strrchr(p, '/');
                if (!e || e == p) {
                        *user = NULL;
                        return 0;
                }

                *e = 0;

                u = hashmap_get(m->user_cgroups, p);
                if (u) {
                        *user = u;
                        return 1;
                }
        }
}

int manager_get_session_by_pid(Manager *m, pid_t pid, Session **session) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(m);
        assert(pid >= 1);
        assert(session);

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &p);
        if (r < 0)
                return r;

        return manager_get_session_by_cgroup(m, p, session);
}

void manager_cgroup_notify_empty(Manager *m, const char *cgroup) {
        Session *s;
        User *u;
        int r;

        r = manager_get_session_by_cgroup(m, cgroup, &s);
        if (r > 0)
                session_add_to_gc_queue(s);

        r = manager_get_user_by_cgroup(m, cgroup, &u);
        if (r > 0)
                user_add_to_gc_queue(u);
}

static void manager_dispatch_other(Manager *m, int fd) {
        Session *s;
        Inhibitor *i;
        Button *b;

        assert_se(m);
        assert_se(fd >= 0);

        s = hashmap_get(m->session_fds, INT_TO_PTR(fd + 1));
        if (s) {
                assert(s->fifo_fd == fd);
                session_remove_fifo(s);
                session_stop(s);
                return;
        }

        i = hashmap_get(m->inhibitor_fds, INT_TO_PTR(fd + 1));
        if (i) {
                assert(i->fifo_fd == fd);
                inhibitor_stop(i);
                inhibitor_free(i);
                return;
        }

        b = hashmap_get(m->button_fds, INT_TO_PTR(fd + 1));
        if (b) {
                assert(b->fd == fd);
                button_process(b);
                return;
        }

        assert_not_reached("Got event for unknown fd");
}

static int manager_connect_bus(Manager *m) {
        DBusError error;
        int r;
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.u32 = FD_BUS,
        };

        assert(m);
        assert(!m->bus);
        assert(m->bus_fd < 0);

        dbus_error_init(&error);

        m->bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!m->bus) {
                log_error("Failed to get system D-Bus connection: %s", bus_error_message(&error));
                r = -ECONNREFUSED;
                goto fail;
        }

        if (!dbus_connection_register_object_path(m->bus, "/org/freedesktop/login1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/login1/seat", &bus_seat_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/login1/session", &bus_session_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/login1/user", &bus_user_vtable, m) ||
            !dbus_connection_add_filter(m->bus, bus_message_filter, m, NULL)) {
                r = log_oom();
                goto fail;
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "interface='org.freedesktop.systemd1.Agent',"
                           "member='Released',"
                           "path='/org/freedesktop/systemd1/agent'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to register match: %s", bus_error_message(&error));
                r = -EIO;
                goto fail;
        }

        r = dbus_bus_request_name(m->bus, "org.freedesktop.login1", DBUS_NAME_FLAG_DO_NOT_QUEUE, &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to register name on bus: %s", bus_error_message(&error));
                r = -EIO;
                goto fail;
        }

        if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)  {
                log_error("Failed to acquire name.");
                r = -EEXIST;
                goto fail;
        }

        m->bus_fd = bus_loop_open(m->bus);
        if (m->bus_fd < 0) {
                r = m->bus_fd;
                goto fail;
        }

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->bus_fd, &ev) < 0)
                goto fail;

        return 0;

fail:
        dbus_error_free(&error);

        return r;
}

static int manager_connect_console(Manager *m) {
        struct epoll_event ev = {
                .events = 0,
                .data.u32 = FD_CONSOLE,
        };

        assert(m);
        assert(m->console_active_fd < 0);

        /* On certain architectures (S390 and Xen, and containers),
           /dev/tty0 does not exist, so don't fail if we can't open
           it. */
        if (access("/dev/tty0", F_OK) < 0) {
                m->console_active_fd = -1;
                return 0;
        }

        m->console_active_fd = open("/sys/class/tty/tty0/active", O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (m->console_active_fd < 0) {

                /* On some systems the device node /dev/tty0 may exist
                 * even though /sys/class/tty/tty0 does not. */
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /sys/class/tty/tty0/active: %m");
                return -errno;
        }

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->console_active_fd, &ev) < 0)
                return -errno;

        return 0;
}

static int manager_connect_udev(Manager *m) {
        int r;
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.u32 = FD_SEAT_UDEV,
        };

        assert(m);
        assert(!m->udev_seat_monitor);
        assert(!m->udev_vcsa_monitor);
        assert(!m->udev_button_monitor);

        m->udev_seat_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
        if (!m->udev_seat_monitor)
                return -ENOMEM;

        r = udev_monitor_filter_add_match_tag(m->udev_seat_monitor, "master-of-seat");
        if (r < 0)
                return r;

        r = udev_monitor_enable_receiving(m->udev_seat_monitor);
        if (r < 0)
                return r;

        m->udev_seat_fd = udev_monitor_get_fd(m->udev_seat_monitor);

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->udev_seat_fd, &ev) < 0)
                return -errno;

        /* Don't watch keys if nobody cares */
        if (m->handle_power_key != HANDLE_IGNORE ||
            m->handle_suspend_key != HANDLE_IGNORE ||
            m->handle_hibernate_key != HANDLE_IGNORE ||
            m->handle_lid_switch != HANDLE_IGNORE) {

                m->udev_button_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
                if (!m->udev_button_monitor)
                        return -ENOMEM;

                r = udev_monitor_filter_add_match_tag(m->udev_button_monitor, "power-switch");
                if (r < 0)
                        return r;

                r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_button_monitor, "input", NULL);
                if (r < 0)
                        return r;

                r = udev_monitor_enable_receiving(m->udev_button_monitor);
                if (r < 0)
                        return r;

                m->udev_button_fd = udev_monitor_get_fd(m->udev_button_monitor);

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.u32 = FD_BUTTON_UDEV;
                if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->udev_button_fd, &ev) < 0)
                        return -errno;
        }

        /* Don't bother watching VCSA devices, if nobody cares */
        if (m->n_autovts > 0 && m->console_active_fd >= 0) {

                m->udev_vcsa_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
                if (!m->udev_vcsa_monitor)
                        return -ENOMEM;

                r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_vcsa_monitor, "vc", NULL);
                if (r < 0)
                        return r;

                r = udev_monitor_enable_receiving(m->udev_vcsa_monitor);
                if (r < 0)
                        return r;

                m->udev_vcsa_fd = udev_monitor_get_fd(m->udev_vcsa_monitor);

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.u32 = FD_VCSA_UDEV;
                if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->udev_vcsa_fd, &ev) < 0)
                        return -errno;
        }

        return 0;
}

void manager_gc(Manager *m, bool drop_not_started) {
        Seat *seat;
        Session *session;
        User *user;

        assert(m);

        while ((seat = m->seat_gc_queue)) {
                LIST_REMOVE(Seat, gc_queue, m->seat_gc_queue, seat);
                seat->in_gc_queue = false;

                if (seat_check_gc(seat, drop_not_started) == 0) {
                        seat_stop(seat);
                        seat_free(seat);
                }
        }

        while ((session = m->session_gc_queue)) {
                LIST_REMOVE(Session, gc_queue, m->session_gc_queue, session);
                session->in_gc_queue = false;

                if (session_check_gc(session, drop_not_started) == 0) {
                        session_stop(session);
                        session_free(session);
                }
        }

        while ((user = m->user_gc_queue)) {
                LIST_REMOVE(User, gc_queue, m->user_gc_queue, user);
                user->in_gc_queue = false;

                if (user_check_gc(user, drop_not_started) == 0) {
                        user_stop(user);
                        user_free(user);
                }
        }
}

int manager_get_idle_hint(Manager *m, dual_timestamp *t) {
        Session *s;
        bool idle_hint;
        dual_timestamp ts = { 0, 0 };
        Iterator i;

        assert(m);

        idle_hint = !manager_is_inhibited(m, INHIBIT_IDLE, INHIBIT_BLOCK, t, false, false, 0);

        HASHMAP_FOREACH(s, m->sessions, i) {
                dual_timestamp k;
                int ih;

                ih = session_get_idle_hint(s, &k);
                if (ih < 0)
                        return ih;

                if (!ih) {
                        if (!idle_hint) {
                                if (k.monotonic < ts.monotonic)
                                        ts = k;
                        } else {
                                idle_hint = false;
                                ts = k;
                        }
                } else if (idle_hint) {

                        if (k.monotonic > ts.monotonic)
                                ts = k;
                }
        }

        if (t)
                *t = ts;

        return idle_hint;
}

int manager_dispatch_idle_action(Manager *m) {
        struct dual_timestamp since;
        struct itimerspec its = {};
        int r;
        usec_t n;

        assert(m);

        if (m->idle_action == HANDLE_IGNORE ||
            m->idle_action_usec <= 0) {
                r = 0;
                goto finish;
        }

        n = now(CLOCK_MONOTONIC);

        r = manager_get_idle_hint(m, &since);
        if (r <= 0)
                /* Not idle. Let's check if after a timeout it might be idle then. */
                timespec_store(&its.it_value, n + m->idle_action_usec);
        else {
                /* Idle! Let's see if it's time to do something, or if
                 * we shall sleep for longer. */

                if (n >= since.monotonic + m->idle_action_usec &&
                    (m->idle_action_not_before_usec <= 0 || n >= m->idle_action_not_before_usec + m->idle_action_usec)) {
                        log_info("System idle. Taking action.");

                        manager_handle_action(m, 0, m->idle_action, false, false);
                        m->idle_action_not_before_usec = n;
                }

                timespec_store(&its.it_value, MAX(since.monotonic, m->idle_action_not_before_usec) + m->idle_action_usec);
        }

        if (m->idle_action_fd < 0) {
                struct epoll_event ev = {
                        .events = EPOLLIN,
                        .data.u32 = FD_IDLE_ACTION,
                };

                m->idle_action_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
                if (m->idle_action_fd < 0) {
                        log_error("Failed to create idle action timer: %m");
                        r = -errno;
                        goto finish;
                }

                if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->idle_action_fd, &ev) < 0) {
                        log_error("Failed to add idle action timer to epoll: %m");
                        r = -errno;
                        goto finish;
                }
        }

        if (timerfd_settime(m->idle_action_fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                log_error("Failed to reset timerfd: %m");
                r = -errno;
                goto finish;
        }

        return 0;

finish:
        if (m->idle_action_fd >= 0) {
                close_nointr_nofail(m->idle_action_fd);
                m->idle_action_fd = -1;
        }

        return r;
}
int manager_startup(Manager *m) {
        int r;
        Seat *seat;
        Session *session;
        User *user;
        Inhibitor *inhibitor;
        Iterator i;

        assert(m);
        assert(m->epoll_fd <= 0);

        cg_shorten_controllers(m->reset_controllers);
        cg_shorten_controllers(m->controllers);

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0)
                return -errno;

        /* Connect to console */
        r = manager_connect_console(m);
        if (r < 0)
                return r;

        /* Connect to udev */
        r = manager_connect_udev(m);
        if (r < 0)
                return r;

        /* Connect to the bus */
        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        /* Instantiate magic seat 0 */
        r = manager_add_seat(m, "seat0", &m->vtconsole);
        if (r < 0)
                return r;

        /* Deserialize state */
        manager_enumerate_devices(m);
        manager_enumerate_seats(m);
        manager_enumerate_users(m);
        manager_enumerate_sessions(m);
        manager_enumerate_inhibitors(m);
        manager_enumerate_buttons(m);

        /* Remove stale objects before we start them */
        manager_gc(m, false);

        /* Reserve the special reserved VT */
        manager_reserve_vt(m);

        /* And start everything */
        HASHMAP_FOREACH(seat, m->seats, i)
                seat_start(seat);

        HASHMAP_FOREACH(user, m->users, i)
                user_start(user);

        HASHMAP_FOREACH(session, m->sessions, i)
                session_start(session);

        HASHMAP_FOREACH(inhibitor, m->inhibitors, i)
                inhibitor_start(inhibitor);

        manager_dispatch_idle_action(m);

        return 0;
}

static int manager_recheck_buttons(Manager *m) {
        Iterator i;
        Button *b;
        int r = 0;

        assert(m);

        HASHMAP_FOREACH(b, m->buttons, i) {
                int q;

                q = button_recheck(b);
                if (q > 0)
                        return 1;
                if (q < 0)
                        r = q;
        }

        return r;
}

int manager_run(Manager *m) {
        assert(m);

        for (;;) {
                struct epoll_event event;
                int n;
                int msec = -1;

                manager_gc(m, true);

                if (manager_dispatch_delayed(m) > 0)
                        continue;

                if (manager_recheck_buttons(m) > 0)
                        continue;

                if (dbus_connection_dispatch(m->bus) != DBUS_DISPATCH_COMPLETE)
                        continue;

                manager_gc(m, true);

                if (m->action_what != 0 && !m->action_job) {
                        usec_t x, y;

                        x = now(CLOCK_MONOTONIC);
                        y = m->action_timestamp + m->inhibit_delay_max;

                        msec = x >= y ? 0 : (int) ((y - x) / USEC_PER_MSEC);
                }

                n = epoll_wait(m->epoll_fd, &event, 1, msec);
                if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("epoll() failed: %m");
                        return -errno;
                }

                if (n == 0)
                        continue;

                switch (event.data.u32) {

                case FD_SEAT_UDEV:
                        manager_dispatch_seat_udev(m);
                        break;

                case FD_VCSA_UDEV:
                        manager_dispatch_vcsa_udev(m);
                        break;

                case FD_BUTTON_UDEV:
                        manager_dispatch_button_udev(m);
                        break;

                case FD_CONSOLE:
                        manager_dispatch_console(m);
                        break;

                case FD_IDLE_ACTION:
                        manager_dispatch_idle_action(m);
                        break;

                case FD_BUS:
                        bus_loop_dispatch(m->bus_fd);
                        break;

                default:
                        if (event.data.u32 >= FD_OTHER_BASE)
                                manager_dispatch_other(m, event.data.u32 - FD_OTHER_BASE);
                }
        }

        return 0;
}

static int manager_parse_config_file(Manager *m) {
        static const char fn[] = "/etc/systemd/logind.conf";
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        f = fopen(fn, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open configuration file %s: %m", fn);
                return -errno;
        }

        r = config_parse(NULL, fn, f, "Login\0", config_item_perf_lookup,
                         (void*) logind_gperf_lookup, false, false, m);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        return r;
}

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_set_facility(LOG_AUTH);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        /* Always create the directories people can create inotify
         * watches in. Note that some applications might check for the
         * existence of /run/systemd/seats/ to determine whether
         * logind is available, so please always make sure this check
         * stays in. */
        mkdir_label("/run/systemd/seats", 0755);
        mkdir_label("/run/systemd/users", 0755);
        mkdir_label("/run/systemd/sessions", 0755);

        m = manager_new();
        if (!m) {
                r = log_oom();
                goto finish;
        }

        manager_parse_config_file(m);

        r = manager_startup(m);
        if (r < 0) {
                log_error("Failed to fully start up daemon: %s", strerror(-r));
                goto finish;
        }

        log_debug("systemd-logind running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = manager_run(m);

        log_debug("systemd-logind stopped as pid %lu", (unsigned long) getpid());

finish:
        sd_notify(false,
                  "STATUS=Shutting down...");

        if (m)
                manager_free(m);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
