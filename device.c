/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include <errno.h>
#include <sys/epoll.h>
#include <libudev.h>

#include "unit.h"
#include "device.h"
#include "strv.h"
#include "log.h"

static const UnitActiveState state_translation_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = UNIT_INACTIVE,
        [DEVICE_AVAILABLE] = UNIT_ACTIVE
};

static const char* const state_string_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = "dead",
        [DEVICE_AVAILABLE] = "available"
};

static void device_done(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        free(d->sysfs);
}

static void device_set_state(Device *d, DeviceState state) {
        DeviceState old_state;
        assert(d);

        old_state = d->state;
        d->state = state;

        log_debug("%s changed %s → %s", unit_id(UNIT(d)), state_string_table[old_state], state_string_table[state]);

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state]);
}

static int device_coldplug(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(d->state == DEVICE_DEAD);

        if (d->sysfs)
                device_set_state(d, DEVICE_AVAILABLE);

        return 0;
}

static void device_dump(Unit *u, FILE *f, const char *prefix) {
        Device *d = DEVICE(u);

        assert(d);

        fprintf(f,
                "%sDevice State: %s\n"
                "%sSysfs Path: %s\n",
                prefix, state_string_table[d->state],
                prefix, strna(d->sysfs));
}

static UnitActiveState device_active_state(Unit *u) {
        assert(u);

        return state_translation_table[DEVICE(u)->state];
}

static int device_add_escaped_name(Unit *u, const char *dn, bool make_id) {
        char *e;
        int r;

        assert(u);
        assert(dn);
        assert(dn[0] == '/');

        if (!(e = unit_name_escape_path(dn+1, ".device")))
                return -ENOMEM;

        r = unit_add_name(u, e);

        if (r >= 0 && make_id)
                unit_choose_id(u, e);

        free(e);

        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

static int device_process_new_device(Manager *m, struct udev_device *dev, bool update_state) {
        const char *dn, *names, *wants, *sysfs;
        Unit *u = NULL;
        int r;
        char *e, *w, *state;
        size_t l;
        bool delete;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(m);

        /* Check whether this entry is even relevant for us. */
        dn = udev_device_get_devnode(dev);
        names = udev_device_get_property_value(dev, "SYSTEMD_NAMES");
        wants = udev_device_get_property_value(dev, "SYSTEMD_WANTS");

        if (!dn && !names && !wants)
                return 0;

        /* Ok, seems kinda interesting. Now, let's see if this one
         * already exists. */

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        assert(sysfs[0] == '/');
        if (!(e = unit_name_escape_path(sysfs+1, ".device")))
                return -ENOMEM;

        if (!(u = manager_get_unit(m, e))) {
                const char *model;

                delete = true;

                if (!(u = unit_new(m))) {
                        free(e);
                        return -ENOMEM;
                }

                r = unit_add_name(u, e);
                free(e);

                if (r < 0)
                        goto fail;

                if (!(DEVICE(u)->sysfs = strdup(sysfs))) {
                        r = -ENOMEM;
                        goto fail;
                }

                if ((model = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE")) ||
                    (model = udev_device_get_property_value(dev, "ID_MODEL")))
                        if ((r = unit_set_description(u, model)) < 0)
                                goto fail;

                unit_add_to_load_queue(u);
        } else {
                delete = false;
                free(e);
        }

        if (dn)
                if ((r = device_add_escaped_name(u, dn, true)) < 0)
                        goto fail;

        first = udev_device_get_devlinks_list_entry(dev);
        udev_list_entry_foreach(item, first)
                if ((r = device_add_escaped_name(u, udev_list_entry_get_name(item), false)) < 0)
                        goto fail;

        if (names) {
                FOREACH_WORD(w, l, names, state) {
                        if (!(e = strndup(w, l)))
                                goto fail;

                        r = unit_add_name(u, e);
                        free(e);

                        if (r < 0 && r != -EEXIST)
                                goto fail;
                }
        }

        if (wants) {
                FOREACH_WORD(w, l, wants, state) {
                        if (!(e = strndup(w, l)))
                                goto fail;

                        r = unit_add_dependency_by_name(u, UNIT_WANTS, e);
                        free(e);

                        if (r < 0)
                                goto fail;
                }
        }

        if (update_state) {
                manager_dispatch_load_queue(u->meta.manager);
                device_set_state(DEVICE(u), DEVICE_AVAILABLE);
        }

        unit_add_to_dbus_queue(u);

        return 0;

fail:
        if (delete && u)
                unit_free(u);
        return r;
}

static int device_process_path(Manager *m, const char *path, bool update_state) {
        int r;
        struct udev_device *dev;

        assert(m);
        assert(path);

        if (!(dev = udev_device_new_from_syspath(m->udev, path))) {
                log_warning("Failed to get udev device object from udev for path %s.", path);
                return -ENOMEM;
        }

        r = device_process_new_device(m, dev, update_state);
        udev_device_unref(dev);
        return r;
}

static int device_process_removed_device(Manager *m, struct udev_device *dev) {
        const char *sysfs;
        char *e;
        Unit *u;
        Device *d;

        assert(m);
        assert(dev);

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        assert(sysfs[0] == '/');
        if (!(e = unit_name_escape_path(sysfs+1, ".device")))
                return -ENOMEM;

        u = manager_get_unit(m, e);
        free(e);

        if (!u)
                return 0;

        d = DEVICE(u);
        free(d->sysfs);
        d->sysfs = NULL;

        device_set_state(d, DEVICE_DEAD);
        return 0;
}

static void device_shutdown(Manager *m) {
        assert(m);

        if (m->udev_monitor)
                udev_monitor_unref(m->udev_monitor);

        if (m->udev)
                udev_unref(m->udev);
}

static int device_enumerate(Manager *m) {
        struct epoll_event ev;
        int r;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(m);

        if (!(m->udev = udev_new()))
                return -ENOMEM;

        if (!(m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev"))) {
                r = -ENOMEM;
                goto fail;
        }

        if (udev_monitor_enable_receiving(m->udev_monitor) < 0) {
                r = -EIO;
                goto fail;
        }

        m->udev_watch.type = WATCH_UDEV;
        m->udev_watch.fd = udev_monitor_get_fd(m->udev_monitor);

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.ptr = &m->udev_watch;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->udev_watch.fd, &ev) < 0)
                return -errno;

        if (!(e = udev_enumerate_new(m->udev))) {
                r = -ENOMEM;
                goto fail;
        }

        if (udev_enumerate_scan_devices(e) < 0) {
                r = -EIO;
                goto fail;
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first)
                device_process_path(m, udev_list_entry_get_name(item), false);

        udev_enumerate_unref(e);
        return 0;

fail:
        if (e)
                udev_enumerate_unref(e);

        device_shutdown(m);
        return r;
}

void device_fd_event(Manager *m, int events) {
        struct udev_device *dev;
        int r;
        const char *action;

        assert(m);
        assert(events == EPOLLIN);

        log_debug("got udev event");

        if (!(dev = udev_monitor_receive_device(m->udev_monitor))) {
                log_error("Failed to receive device.");
                return;
        }

        if (!(action = udev_device_get_action(dev))) {
                log_error("Failed to get udev action string.");
                goto fail;
        }

        if (streq(action, "remove")) {
                if ((r = device_process_removed_device(m, dev)) < 0) {
                        log_error("Failed to process udev device event: %s", strerror(-r));
                        goto fail;
                }
        } else {
                if ((r = device_process_new_device(m, dev, true)) < 0) {
                        log_error("Failed to process udev device event: %s", strerror(-r));
                        goto fail;
                }
        }

fail:
        udev_device_unref(dev);
}

const UnitVTable device_vtable = {
        .suffix = ".device",

        .init = unit_load_fragment_and_dropin,
        .done = device_done,
        .coldplug = device_coldplug,

        .dump = device_dump,

        .active_state = device_active_state,

        .enumerate = device_enumerate,
        .shutdown = device_shutdown
};
