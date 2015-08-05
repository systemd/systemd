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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pwd.h>
#include <linux/vt.h>

#include "strv.h"
#include "cgroup-util.h"
#include "bus-util.h"
#include "bus-error.h"
#include "udev-util.h"
#include "logind.h"
#include "terminal-util.h"

int manager_add_device(Manager *m, const char *sysfs, bool master, Device **_device) {
        Device *d;

        assert(m);
        assert(sysfs);

        d = hashmap_get(m->devices, sysfs);
        if (d)
                /* we support adding master-flags, but not removing them */
                d->master = d->master || master;
        else {
                d = device_new(m, sysfs, master);
                if (!d)
                        return -ENOMEM;
        }

        if (_device)
                *_device = d;

        return 0;
}

int manager_add_seat(Manager *m, const char *id, Seat **_seat) {
        Seat *s;

        assert(m);
        assert(id);

        s = hashmap_get(m->seats, id);
        if (!s) {
                s = seat_new(m, id);
                if (!s)
                        return -ENOMEM;
        }

        if (_seat)
                *_seat = s;

        return 0;
}

int manager_add_session(Manager *m, const char *id, Session **_session) {
        Session *s;

        assert(m);
        assert(id);

        s = hashmap_get(m->sessions, id);
        if (!s) {
                s = session_new(m, id);
                if (!s)
                        return -ENOMEM;
        }

        if (_session)
                *_session = s;

        return 0;
}

int manager_add_user(Manager *m, uid_t uid, gid_t gid, const char *name, User **_user) {
        User *u;

        assert(m);
        assert(name);

        u = hashmap_get(m->users, UID_TO_PTR(uid));
        if (!u) {
                u = user_new(m, uid, gid, name);
                if (!u)
                        return -ENOMEM;
        }

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
        if (!b) {
                b = button_new(m, name);
                if (!b)
                        return -ENOMEM;
        }

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
                Seat *seat = NULL;
                bool master;

                sn = udev_device_get_property_value(d, "ID_SEAT");
                if (isempty(sn))
                        sn = "seat0";

                if (!seat_name_is_valid(sn)) {
                        log_warning("Device with invalid seat name %s found, ignoring.", sn);
                        return 0;
                }

                seat = hashmap_get(m->seats, sn);
                master = udev_device_has_tag(d, "master-of-seat");

                /* Ignore non-master devices for unknown seats */
                if (!master && !seat)
                        return 0;

                r = manager_add_device(m, udev_device_get_syspath(d), master, &device);
                if (r < 0)
                        return r;

                if (!seat) {
                        r = manager_add_seat(m, sn, &seat);
                        if (r < 0) {
                                if (!device->seat)
                                        device_free(device);

                                return r;
                        }
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

int manager_get_session_by_pid(Manager *m, pid_t pid, Session **session) {
        _cleanup_free_ char *unit = NULL;
        Session *s;
        int r;

        assert(m);

        if (pid < 1)
                return -EINVAL;

        r = cg_pid_get_unit(pid, &unit);
        if (r < 0)
                return 0;

        s = hashmap_get(m->session_units, unit);
        if (!s)
                return 0;

        if (session)
                *session = s;
        return 1;
}

int manager_get_user_by_pid(Manager *m, pid_t pid, User **user) {
        _cleanup_free_ char *unit = NULL;
        User *u;
        int r;

        assert(m);
        assert(user);

        if (pid < 1)
                return -EINVAL;

        r = cg_pid_get_slice(pid, &unit);
        if (r < 0)
                return 0;

        u = hashmap_get(m->user_units, unit);
        if (!u)
                return 0;

        *user = u;
        return 1;
}

int manager_get_idle_hint(Manager *m, dual_timestamp *t) {
        Session *s;
        bool idle_hint;
        dual_timestamp ts = DUAL_TIMESTAMP_NULL;
        Iterator i;

        assert(m);

        idle_hint = !manager_is_inhibited(m, INHIBIT_IDLE, INHIBIT_BLOCK, t, false, false, 0, NULL);

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

bool manager_shall_kill(Manager *m, const char *user) {
        assert(m);
        assert(user);

        if (!m->kill_user_processes)
                return false;

        if (strv_contains(m->kill_exclude_users, user))
                return false;

        if (strv_isempty(m->kill_only_users))
                return true;

        return strv_contains(m->kill_only_users, user);
}

static int vt_is_busy(unsigned int vtnr) {
        struct vt_stat vt_stat;
        int r = 0;
        _cleanup_close_ int fd;

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

        return r;
}

int manager_spawn_autovt(Manager *m, unsigned int vtnr) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char name[sizeof("autovt@tty.service") + DECIMAL_STR_MAX(unsigned int)];
        int r;

        assert(m);
        assert(vtnr >= 1);

        if (vtnr > m->n_autovts &&
            vtnr != m->reserve_vt)
                return 0;

        if (vtnr != m->reserve_vt) {
                /* If this is the reserved TTY, we'll start the getty
                 * on it in any case, but otherwise only if it is not
                 * busy. */

                r = vt_is_busy(vtnr);
                if (r < 0)
                        return r;
                else if (r > 0)
                        return -EBUSY;
        }

        snprintf(name, sizeof(name), "autovt@tty%u.service", vtnr);
        r = sd_bus_call_method(
                        m->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        &error,
                        NULL,
                        "ss", name, "fail");
        if (r < 0)
                log_error("Failed to start %s: %s", name, bus_error_message(&error, r));

        return r;
}

static bool manager_is_docked(Manager *m) {
        Iterator i;
        Button *b;

        HASHMAP_FOREACH(b, m->buttons, i)
                if (b->docked)
                        return true;

        return false;
}

static int manager_count_external_displays(Manager *m) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;
        int r;
        int n = 0;

        e = udev_enumerate_new(m->udev);
        if (!e)
                return -ENOMEM;

        r = udev_enumerate_add_match_subsystem(e, "drm");
        if (r < 0)
                return r;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                return r;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;
                struct udev_device *p;
                const char *status, *enabled, *dash, *nn, *i;
                bool external = false;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d)
                        return -ENOMEM;

                p = udev_device_get_parent(d);
                if (!p)
                        continue;

                /* If the parent shares the same subsystem as the
                 * device we are looking at then it is a connector,
                 * which is what we are interested in. */
                if (!streq_ptr(udev_device_get_subsystem(p), "drm"))
                        continue;

                nn = udev_device_get_sysname(d);
                if (!nn)
                        continue;

                /* Ignore internal displays: the type is encoded in
                 * the sysfs name, as the second dash seperated item
                 * (the first is the card name, the last the connector
                 * number). We implement a whitelist of external
                 * displays here, rather than a whitelist, to ensure
                 * we don't block suspends too eagerly. */
                dash = strchr(nn, '-');
                if (!dash)
                        continue;

                dash++;
                FOREACH_STRING(i, "VGA-", "DVI-I-", "DVI-D-", "DVI-A-"
                               "Composite-", "SVIDEO-", "Component-",
                               "DIN-", "DP-", "HDMI-A-", "HDMI-B-", "TV-") {

                        if (startswith(dash, i)) {
                                external = true;
                                break;
                        }
                }
                if (!external)
                        continue;

                /* Ignore ports that are not enabled */
                enabled = udev_device_get_sysattr_value(d, "enabled");
                if (!enabled)
                        continue;
                if (!streq_ptr(enabled, "enabled"))
                        continue;

                /* We count any connector which is not explicitly
                 * "disconnected" as connected. */
                status = udev_device_get_sysattr_value(d, "status");
                if (!streq_ptr(status, "disconnected"))
                        n++;
        }

        return n;
}

bool manager_is_docked_or_external_displays(Manager *m) {
        int n;

        /* If we are docked don't react to lid closing */
        if (manager_is_docked(m)) {
                log_debug("System is docked.");
                return true;
        }

        /* If we have more than one display connected,
         * assume that we are docked. */
        n = manager_count_external_displays(m);
        if (n < 0)
                log_warning_errno(n, "Display counting failed: %m");
        else if (n >= 1) {
                log_debug("External (%i) displays connected.", n);
                return true;
        }

        return false;
}
