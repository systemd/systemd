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
#include "unit-name.h"
#include "dbus-device.h"

static const UnitActiveState state_translation_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = UNIT_INACTIVE,
        [DEVICE_PLUGGED] = UNIT_ACTIVE
};

static void device_unset_sysfs(Device *d) {
        Device *first;

        assert(d);

        if (d->sysfs) {
                /* Remove this unit from the chain of devices which share the
                 * same sysfs path. */
                first = hashmap_get(d->meta.manager->devices_by_sysfs, d->sysfs);
                LIST_REMOVE(Device, same_sysfs, first, d);

                if (first)
                        hashmap_remove_and_replace(d->meta.manager->devices_by_sysfs, d->sysfs, first->sysfs, first);
                else
                        hashmap_remove(d->meta.manager->devices_by_sysfs, d->sysfs);

                free(d->sysfs);
                d->sysfs = NULL;
        }

        d->meta.following = NULL;
}

static void device_init(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(d->meta.load_state == UNIT_STUB);

        /* In contrast to all other unit types we timeout jobs waiting
         * for devices by default. This is because they otherwise wait
         * indefinetely for plugged in devices, something which cannot
         * happen for the other units since their operations time out
         * anyway. */
        d->meta.job_timeout = DEFAULT_TIMEOUT_USEC;
}

static void device_done(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);

        device_unset_sysfs(d);
}

static void device_set_state(Device *d, DeviceState state) {
        DeviceState old_state;
        assert(d);

        old_state = d->state;
        d->state = state;

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          d->meta.id,
                          device_state_to_string(old_state),
                          device_state_to_string(state));

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state]);
}

static int device_coldplug(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(d->state == DEVICE_DEAD);

        if (d->sysfs)
                device_set_state(d, DEVICE_PLUGGED);

        return 0;
}

static void device_dump(Unit *u, FILE *f, const char *prefix) {
        Device *d = DEVICE(u);

        assert(d);

        fprintf(f,
                "%sDevice State: %s\n"
                "%sSysfs Path: %s\n",
                prefix, device_state_to_string(d->state),
                prefix, strna(d->sysfs));
}

static UnitActiveState device_active_state(Unit *u) {
        assert(u);

        return state_translation_table[DEVICE(u)->state];
}

static const char *device_sub_state_to_string(Unit *u) {
        assert(u);

        return device_state_to_string(DEVICE(u)->state);
}

static int device_add_escaped_name(Unit *u, const char *dn) {
        char *e;
        int r;

        assert(u);
        assert(dn);
        assert(dn[0] == '/');

        if (!(e = unit_name_from_path(dn, ".device")))
                return -ENOMEM;

        r = unit_add_name(u, e);
        free(e);

        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

static int device_find_escape_name(Manager *m, const char *dn, Unit **_u) {
        char *e;
        Unit *u;

        assert(m);
        assert(dn);
        assert(dn[0] == '/');
        assert(_u);

        if (!(e = unit_name_from_path(dn, ".device")))
                return -ENOMEM;

        u = manager_get_unit(m, e);
        free(e);

        if (u) {
                *_u = u;
                return 1;
        }

        return 0;
}

static int device_update_unit(Manager *m, struct udev_device *dev, const char *path, bool main) {
        const char *sysfs, *model;
        Unit *u = NULL;
        int r;
        bool delete;

        assert(m);

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        if ((r = device_find_escape_name(m, path, &u)) < 0)
                return r;

        /* If this is a different unit, then let's not merge things */
        if (u && DEVICE(u)->sysfs && !path_equal(DEVICE(u)->sysfs, sysfs)) {
                log_error("Hmm, something's broken. Asked to create two devices with same name but different sysfs paths.");
                return -EEXIST;
        }

        if (!u) {
                Device *first;
                delete = true;

                if (!(u = unit_new(m)))
                        return -ENOMEM;

                if ((r = device_add_escaped_name(u, path)) < 0)
                        goto fail;

                if (!(DEVICE(u)->sysfs = strdup(sysfs))) {
                        r = -ENOMEM;
                        goto fail;
                }

                unit_add_to_load_queue(u);

                if (!m->devices_by_sysfs)
                        if (!(m->devices_by_sysfs = hashmap_new(string_hash_func, string_compare_func))) {
                                r = -ENOMEM;
                                goto fail;
                        }

                first = hashmap_get(m->devices_by_sysfs, sysfs);
                LIST_PREPEND(Device, same_sysfs, first, DEVICE(u));

                if ((r = hashmap_replace(m->devices_by_sysfs, DEVICE(u)->sysfs, first)) < 0)
                        goto fail;

        } else
                delete = false;

        if ((model = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE")) ||
            (model = udev_device_get_property_value(dev, "ID_MODEL"))) {
                if ((r = unit_set_description(u, model)) < 0)
                        goto fail;
        } else
                if ((r = unit_set_description(u, path)) < 0)
                        goto fail;

        if (main) {
                /* The additional systemd udev properties we only
                 * interpret for the main object */
                const char *wants, *alias;

                if ((alias = udev_device_get_property_value(dev, "SYSTEMD_ALIAS"))) {
                        if (!is_path(alias))
                                log_warning("SYSTEMD_ALIAS for %s is not a path, ignoring: %s", sysfs, alias);
                        else {
                                if ((r = device_add_escaped_name(u, alias)) < 0)
                                        goto fail;
                        }
                }

                if ((wants = udev_device_get_property_value(dev, "SYSTEMD_WANTS"))) {
                        char *state, *w;
                        size_t l;

                        FOREACH_WORD_QUOTED(w, l, wants, state) {
                                char *e;

                                if (!(e = strndup(w, l))) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                r = unit_add_dependency_by_name(u, UNIT_WANTS, e, NULL, true);
                                free(e);

                                if (r < 0)
                                        goto fail;
                        }
                }

                u->meta.following = NULL;
        } else
                device_find_escape_name(m, sysfs, &u->meta.following);

        unit_add_to_dbus_queue(u);
        return 0;

fail:
        log_warning("Failed to load device unit: %s", strerror(-r));

        if (delete && u)
                unit_free(u);

        return r;
}

static int device_process_new_device(Manager *m, struct udev_device *dev, bool update_state) {
        const char *sysfs, *dn;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(m);

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        /* Add the main unit named after the sysfs path */
        device_update_unit(m, dev, sysfs, true);

        /* Add an additional unit for the device node */
        if ((dn = udev_device_get_devnode(dev)))
                device_update_unit(m, dev, dn, false);

        /* Add additional units for all symlinks */
        first = udev_device_get_devlinks_list_entry(dev);
        udev_list_entry_foreach(item, first) {
                const char *p;

                /* Don't bother with the /dev/block links */
                p = udev_list_entry_get_name(item);

                if (path_startswith(p, "/dev/block/") ||
                    path_startswith(p, "/dev/char/"))
                        continue;

                device_update_unit(m, dev, p, false);
        }

        if (update_state) {
                Device *d, *l;

                manager_dispatch_load_queue(m);

                l = hashmap_get(m->devices_by_sysfs, sysfs);
                LIST_FOREACH(same_sysfs, d, l)
                        device_set_state(d, DEVICE_PLUGGED);
        }

        return 0;
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
        Device *d;

        assert(m);
        assert(dev);

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        /* Remove all units of this sysfs path */
        while ((d = hashmap_get(m->devices_by_sysfs, sysfs))) {
                device_unset_sysfs(d);
                device_set_state(d, DEVICE_DEAD);
        }

        return 0;
}

static void device_shutdown(Manager *m) {
        assert(m);

        if (m->udev_monitor) {
                udev_monitor_unref(m->udev_monitor);
                m->udev_monitor = NULL;
        }

        if (m->udev) {
                udev_unref(m->udev);
                m->udev = NULL;
        }

        hashmap_free(m->devices_by_sysfs);
        m->devices_by_sysfs = NULL;
}

static int device_enumerate(Manager *m) {
        struct epoll_event ev;
        int r;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(m);

        if (!m->udev) {
                if (!(m->udev = udev_new()))
                        return -ENOMEM;

                if (!(m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev"))) {
                        r = -ENOMEM;
                        goto fail;
                }

                if (udev_monitor_filter_add_match_tag(m->udev_monitor, "systemd") < 0) {
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
        }

        if (!(e = udev_enumerate_new(m->udev))) {
                r = -ENOMEM;
                goto fail;
        }
        if (udev_enumerate_add_match_tag(e, "systemd") < 0) {
                r = -EIO;
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

static const char* const device_state_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = "dead",
        [DEVICE_PLUGGED] = "plugged"
};

DEFINE_STRING_TABLE_LOOKUP(device_state, DeviceState);

const UnitVTable device_vtable = {
        .suffix = ".device",

        .no_requires = true,
        .no_instances = true,
        .no_snapshots = true,
        .no_isolate = true,
        .no_alias = true,

        .init = device_init,

        .load = unit_load_fragment_and_dropin_optional,
        .done = device_done,
        .coldplug = device_coldplug,

        .dump = device_dump,

        .active_state = device_active_state,
        .sub_state_to_string = device_sub_state_to_string,

        .bus_message_handler = bus_device_message_handler,

        .enumerate = device_enumerate,
        .shutdown = device_shutdown
};
