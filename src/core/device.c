/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <sys/epoll.h>
#include <libudev.h>

#include "strv.h"
#include "log.h"
#include "unit-name.h"
#include "dbus-device.h"
#include "def.h"
#include "path-util.h"
#include "udev-util.h"
#include "unit.h"
#include "swap.h"
#include "device.h"

static const UnitActiveState state_translation_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = UNIT_INACTIVE,
        [DEVICE_PLUGGED] = UNIT_ACTIVE
};

static int device_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);

static void device_unset_sysfs(Device *d) {
        Hashmap *devices;
        Device *first;

        assert(d);

        if (!d->sysfs)
                return;

        /* Remove this unit from the chain of devices which share the
         * same sysfs path. */
        devices = UNIT(d)->manager->devices_by_sysfs;
        first = hashmap_get(devices, d->sysfs);
        LIST_REMOVE(same_sysfs, first, d);

        if (first)
                hashmap_remove_and_replace(devices, d->sysfs, first->sysfs, first);
        else
                hashmap_remove(devices, d->sysfs);

        free(d->sysfs);
        d->sysfs = NULL;
}

static void device_init(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(UNIT(d)->load_state == UNIT_STUB);

        /* In contrast to all other unit types we timeout jobs waiting
         * for devices by default. This is because they otherwise wait
         * indefinitely for plugged in devices, something which cannot
         * happen for the other units since their operations time out
         * anyway. */
        u->job_timeout = u->manager->default_timeout_start_usec;

        u->ignore_on_isolate = true;
        u->ignore_on_snapshot = true;
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
                log_debug_unit(UNIT(d)->id,
                               "%s changed %s -> %s", UNIT(d)->id,
                               device_state_to_string(old_state),
                               device_state_to_string(state));

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state], true);
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

_pure_ static UnitActiveState device_active_state(Unit *u) {
        assert(u);

        return state_translation_table[DEVICE(u)->state];
}

_pure_ static const char *device_sub_state_to_string(Unit *u) {
        assert(u);

        return device_state_to_string(DEVICE(u)->state);
}

static int device_add_escaped_name(Unit *u, const char *dn) {
        _cleanup_free_ char *e = NULL;
        int r;

        assert(u);
        assert(dn);
        assert(dn[0] == '/');

        e = unit_name_from_path(dn, ".device");
        if (!e)
                return -ENOMEM;

        r = unit_add_name(u, e);
        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

static int device_find_escape_name(Manager *m, const char *dn, Unit **_u) {
        _cleanup_free_ char *e = NULL;
        Unit *u;

        assert(m);
        assert(dn);
        assert(dn[0] == '/');
        assert(_u);

        e = unit_name_from_path(dn, ".device");
        if (!e)
                return -ENOMEM;

        u = manager_get_unit(m, e);
        if (u) {
                *_u = u;
                return 1;
        }

        return 0;
}

static int device_make_description(Unit *u, struct udev_device *dev, const char *path) {
        const char *model;

        assert(u);
        assert(dev);
        assert(path);

        model = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE");
        if (!model)
                model = udev_device_get_property_value(dev, "ID_MODEL");

        if (model) {
                const char *label;

                /* Try to concatenate the device model string with a label, if there is one */
                label = udev_device_get_property_value(dev, "ID_FS_LABEL");
                if (!label)
                        label = udev_device_get_property_value(dev, "ID_PART_ENTRY_NAME");
                if (!label)
                        label = udev_device_get_property_value(dev, "ID_PART_ENTRY_NUMBER");

                if (label) {
                        _cleanup_free_ char *j;

                        j = strjoin(model, " ", label, NULL);
                        if (j)
                                return unit_set_description(u, j);
                }

                return unit_set_description(u, model);
        }

        return unit_set_description(u, path);
}

static int device_add_udev_wants(Unit *u, struct udev_device *dev) {
        const char *wants;
        char *state, *w;
        size_t l;
        int r;

        assert(u);
        assert(dev);

        wants = udev_device_get_property_value(
                        dev,
                        u->manager->running_as == SYSTEMD_USER ? "SYSTEMD_USER_WANTS" : "SYSTEMD_WANTS");

        if (!wants)
                return 0;

        FOREACH_WORD_QUOTED(w, l, wants, state) {
                _cleanup_free_ char *n = NULL;
                char e[l+1];

                memcpy(e, w, l);
                e[l] = 0;

                n = unit_name_mangle(e, MANGLE_NOGLOB);
                if (!n)
                        return -ENOMEM;

                r = unit_add_dependency_by_name(u, UNIT_WANTS, n, NULL, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int device_update_unit(Manager *m, struct udev_device *dev, const char *path, bool main) {
        const char *sysfs;
        Unit *u = NULL;
        bool delete;
        int r;

        assert(m);
        assert(dev);
        assert(path);

        sysfs = udev_device_get_syspath(dev);
        if (!sysfs)
                return 0;

        r = device_find_escape_name(m, path, &u);
        if (r < 0)
                return r;

        if (u && DEVICE(u)->sysfs && !path_equal(DEVICE(u)->sysfs, sysfs))
                return -EEXIST;

        if (!u) {
                delete = true;

                u = unit_new(m, sizeof(Device));
                if (!u)
                        return log_oom();

                r = device_add_escaped_name(u, path);
                if (r < 0)
                        goto fail;

                unit_add_to_load_queue(u);
        } else
                delete = false;

        /* If this was created via some dependency and has not
         * actually been seen yet ->sysfs will not be
         * initialized. Hence initialize it if necessary. */

        if (!DEVICE(u)->sysfs) {
                Device *first;

                DEVICE(u)->sysfs = strdup(sysfs);
                if (!DEVICE(u)->sysfs) {
                        r = -ENOMEM;
                        goto fail;
                }

                r = hashmap_ensure_allocated(&m->devices_by_sysfs, string_hash_func, string_compare_func);
                if (r < 0)
                        goto fail;

                first = hashmap_get(m->devices_by_sysfs, sysfs);
                LIST_PREPEND(same_sysfs, first, DEVICE(u));

                r = hashmap_replace(m->devices_by_sysfs, DEVICE(u)->sysfs, first);
                if (r < 0)
                        goto fail;
        }

        device_make_description(u, dev, path);

        if (main) {
                /* The additional systemd udev properties we only
                 * interpret for the main object */

                r = device_add_udev_wants(u, dev);
                if (r < 0)
                        goto fail;
        }

        /* Note that this won't dispatch the load queue, the caller
         * has to do that if needed and appropriate */

        unit_add_to_dbus_queue(u);
        return 0;

fail:
        log_warning("Failed to load device unit: %s", strerror(-r));

        if (delete && u)
                unit_free(u);

        return r;
}

static int device_process_new_device(Manager *m, struct udev_device *dev) {
        const char *sysfs, *dn, *alias;
        struct udev_list_entry *item = NULL, *first = NULL;
        int r;

        assert(m);

        sysfs = udev_device_get_syspath(dev);
        if (!sysfs)
                return 0;

        /* Add the main unit named after the sysfs path */
        r = device_update_unit(m, dev, sysfs, true);
        if (r < 0)
                return r;

        /* Add an additional unit for the device node */
        dn = udev_device_get_devnode(dev);
        if (dn)
                device_update_unit(m, dev, dn, false);

        /* Add additional units for all symlinks */
        first = udev_device_get_devlinks_list_entry(dev);
        udev_list_entry_foreach(item, first) {
                const char *p;
                struct stat st;

                /* Don't bother with the /dev/block links */
                p = udev_list_entry_get_name(item);

                if (path_startswith(p, "/dev/block/") ||
                    path_startswith(p, "/dev/char/"))
                        continue;

                /* Verify that the symlink in the FS actually belongs
                 * to this device. This is useful to deal with
                 * conflicting devices, e.g. when two disks want the
                 * same /dev/disk/by-label/xxx link because they have
                 * the same label. We want to make sure that the same
                 * device that won the symlink wins in systemd, so we
                 * check the device node major/minor*/
                if (stat(p, &st) >= 0)
                        if ((!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode)) ||
                            st.st_rdev != udev_device_get_devnum(dev))
                                continue;

                device_update_unit(m, dev, p, false);
        }

        /* Add additional units for all explicitly configured
         * aliases */
        alias = udev_device_get_property_value(dev, "SYSTEMD_ALIAS");
        if (alias) {
                char *state, *w;
                size_t l;

                FOREACH_WORD_QUOTED(w, l, alias, state) {
                        char e[l+1];

                        memcpy(e, w, l);
                        e[l] = 0;

                        if (path_is_absolute(e))
                                device_update_unit(m, dev, e, false);
                        else
                                log_warning("SYSTEMD_ALIAS for %s is not an absolute path, ignoring: %s", sysfs, e);
                }
        }

        return 0;
}

static void device_set_path_plugged(Manager *m, struct udev_device *dev) {
        const char *sysfs;
        Device *d, *l;

        assert(m);
        assert(dev);

        sysfs = udev_device_get_syspath(dev);
        if (!sysfs)
                return;

        l = hashmap_get(m->devices_by_sysfs, sysfs);
        LIST_FOREACH(same_sysfs, d, l)
                device_set_state(d, DEVICE_PLUGGED);
}

static int device_process_removed_device(Manager *m, struct udev_device *dev) {
        const char *sysfs;
        Device *d;

        assert(m);
        assert(dev);

        sysfs = udev_device_get_syspath(dev);
        if (!sysfs)
                return -ENOMEM;

        /* Remove all units of this sysfs path */
        while ((d = hashmap_get(m->devices_by_sysfs, sysfs))) {
                device_unset_sysfs(d);
                device_set_state(d, DEVICE_DEAD);
        }

        return 0;
}

static bool device_is_ready(struct udev_device *dev) {
        const char *ready;

        assert(dev);

        ready = udev_device_get_property_value(dev, "SYSTEMD_READY");
        if (!ready)
                return true;

        return parse_boolean(ready) != 0;
}

static int device_process_new_path(Manager *m, const char *path) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;

        assert(m);
        assert(path);

        dev = udev_device_new_from_syspath(m->udev, path);
        if (!dev)
                return log_oom();

        if (!device_is_ready(dev))
                return 0;

        return device_process_new_device(m, dev);
}

static Unit *device_following(Unit *u) {
        Device *d = DEVICE(u);
        Device *other, *first = NULL;

        assert(d);

        if (startswith(u->id, "sys-"))
                return NULL;

        /* Make everybody follow the unit that's named after the sysfs path */
        for (other = d->same_sysfs_next; other; other = other->same_sysfs_next)
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

        for (other = d->same_sysfs_prev; other; other = other->same_sysfs_prev) {
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

                first = other;
        }

        return UNIT(first);
}

static int device_following_set(Unit *u, Set **_set) {
        Device *d = DEVICE(u), *other;
        Set *set;
        int r;

        assert(d);
        assert(_set);

        if (LIST_JUST_US(same_sysfs, d)) {
                *_set = NULL;
                return 0;
        }

        set = set_new(NULL, NULL);
        if (!set)
                return -ENOMEM;

        LIST_FOREACH_AFTER(same_sysfs, other, d) {
                r = set_put(set, other);
                if (r < 0)
                        goto fail;
        }

        LIST_FOREACH_BEFORE(same_sysfs, other, d) {
                r = set_put(set, other);
                if (r < 0)
                        goto fail;
        }

        *_set = set;
        return 1;

fail:
        set_free(set);
        return r;
}

static void device_shutdown(Manager *m) {
        assert(m);

        m->udev_event_source = sd_event_source_unref(m->udev_event_source);

        if (m->udev_monitor) {
                udev_monitor_unref(m->udev_monitor);
                m->udev_monitor = NULL;
        }

        hashmap_free(m->devices_by_sysfs);
        m->devices_by_sysfs = NULL;
}

static int device_enumerate(Manager *m) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;
        int r;

        assert(m);

        if (!m->udev_monitor) {
                m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
                if (!m->udev_monitor) {
                        r = -ENOMEM;
                        goto fail;
                }

                /* This will fail if we are unprivileged, but that
                 * should not matter much, as user instances won't run
                 * during boot. */
                udev_monitor_set_receive_buffer_size(m->udev_monitor, 128*1024*1024);

                r = udev_monitor_filter_add_match_tag(m->udev_monitor, "systemd");
                if (r < 0)
                        goto fail;

                r = udev_monitor_enable_receiving(m->udev_monitor);
                if (r < 0)
                        goto fail;

                r = sd_event_add_io(m->event, &m->udev_event_source, udev_monitor_get_fd(m->udev_monitor), EPOLLIN, device_dispatch_io, m);
                if (r < 0)
                        goto fail;
        }

        e = udev_enumerate_new(m->udev);
        if (!e) {
                r = -ENOMEM;
                goto fail;
        }

        r = udev_enumerate_add_match_tag(e, "systemd");
        if (r < 0)
                goto fail;

        r = udev_enumerate_add_match_is_initialized(e);
        if (r < 0)
                goto fail;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                goto fail;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first)
                device_process_new_path(m, udev_list_entry_get_name(item));

        return 0;

fail:
        device_shutdown(m);
        return r;
}

static int device_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        Manager *m = userdata;
        const char *action;
        int r;

        assert(m);

        if (revents != EPOLLIN) {
                static RATELIMIT_DEFINE(limit, 10*USEC_PER_SEC, 5);

                if (!ratelimit_test(&limit))
                        log_error("Failed to get udev event: %m");
                if (!(revents & EPOLLIN))
                        return 0;
        }

        /*
         * libudev might filter-out devices which pass the bloom
         * filter, so getting NULL here is not necessarily an error.
         */
        dev = udev_monitor_receive_device(m->udev_monitor);
        if (!dev)
                return 0;

        action = udev_device_get_action(dev);
        if (!action) {
                log_error("Failed to get udev action string.");
                return 0;
        }

        if (streq(action, "remove") || !device_is_ready(dev))  {
                r = device_process_removed_device(m, dev);
                if (r < 0)
                        log_error("Failed to process device remove event: %s", strerror(-r));

                r = swap_process_removed_device(m, dev);
                if (r < 0)
                        log_error("Failed to process swap device remove event: %s", strerror(-r));

        } else {
                r = device_process_new_device(m, dev);
                if (r < 0)
                        log_error("Failed to process device new event: %s", strerror(-r));

                r = swap_process_new_device(m, dev);
                if (r < 0)
                        log_error("Failed to process swap device new event: %s", strerror(-r));

                manager_dispatch_load_queue(m);

                device_set_path_plugged(m, dev);
        }

        return 0;
}

static const char* const device_state_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = "dead",
        [DEVICE_PLUGGED] = "plugged"
};

DEFINE_STRING_TABLE_LOOKUP(device_state, DeviceState);

const UnitVTable device_vtable = {
        .object_size = sizeof(Device),
        .sections =
                "Unit\0"
                "Device\0"
                "Install\0",

        .no_instances = true,

        .init = device_init,
        .done = device_done,
        .load = unit_load_fragment_and_dropin_optional,

        .coldplug = device_coldplug,

        .dump = device_dump,

        .active_state = device_active_state,
        .sub_state_to_string = device_sub_state_to_string,

        .bus_interface = "org.freedesktop.systemd1.Device",
        .bus_vtable = bus_device_vtable,

        .following = device_following,
        .following_set = device_following_set,

        .enumerate = device_enumerate,
        .shutdown = device_shutdown,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Expecting device %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Found device %s.",
                        [JOB_TIMEOUT]    = "Timed out waiting for device %s.",
                },
        },
};
