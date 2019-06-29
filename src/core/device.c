/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sys/epoll.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "dbus-device.h"
#include "dbus-unit.h"
#include "device-private.h"
#include "device-util.h"
#include "device.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "serialize.h"
#include "stat-util.h"
#include "string-util.h"
#include "swap.h"
#include "udev-util.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = UNIT_INACTIVE,
        [DEVICE_TENTATIVE] = UNIT_ACTIVATING,
        [DEVICE_PLUGGED] = UNIT_ACTIVE,
};

static int device_dispatch_io(sd_device_monitor *monitor, sd_device *dev, void *userdata);
static void device_update_found_one(Device *d, DeviceFound found, DeviceFound mask);

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

        d->sysfs = mfree(d->sysfs);
}

static int device_set_sysfs(Device *d, const char *sysfs) {
        _cleanup_free_ char *copy = NULL;
        Device *first;
        int r;

        assert(d);

        if (streq_ptr(d->sysfs, sysfs))
                return 0;

        r = hashmap_ensure_allocated(&UNIT(d)->manager->devices_by_sysfs, &path_hash_ops);
        if (r < 0)
                return r;

        copy = strdup(sysfs);
        if (!copy)
                return -ENOMEM;

        device_unset_sysfs(d);

        first = hashmap_get(UNIT(d)->manager->devices_by_sysfs, sysfs);
        LIST_PREPEND(same_sysfs, first, d);

        r = hashmap_replace(UNIT(d)->manager->devices_by_sysfs, copy, first);
        if (r < 0) {
                LIST_REMOVE(same_sysfs, first, d);
                return r;
        }

        d->sysfs = TAKE_PTR(copy);
        return 0;
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
        u->job_running_timeout = u->manager->default_timeout_start_usec;

        u->ignore_on_isolate = true;

        d->deserialized_state = _DEVICE_STATE_INVALID;
}

static void device_done(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);

        device_unset_sysfs(d);
        d->wants_property = strv_free(d->wants_property);
}

static int device_load(Unit *u) {
        int r;

        r = unit_load_fragment_and_dropin_optional(u);
        if (r < 0)
                return r;

        if (!u->description) {
                /* Generate a description based on the path, to be used until the
                   device is initialized properly */
                r = unit_name_to_path(u->id, &u->description);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to unescape name: %m");
        }

        return 0;
}

static void device_set_state(Device *d, DeviceState state) {
        DeviceState old_state;
        assert(d);

        if (d->state != state)
                bus_unit_send_pending_change_signal(UNIT(d), false);

        old_state = d->state;
        d->state = state;

        if (state == DEVICE_DEAD)
                device_unset_sysfs(d);

        if (state != old_state)
                log_unit_debug(UNIT(d), "Changed %s -> %s", device_state_to_string(old_state), device_state_to_string(state));

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state], 0);
}

static int device_coldplug(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(d->state == DEVICE_DEAD);

        /* First, let's put the deserialized state and found mask into effect, if we have it. */

        if (d->deserialized_state < 0 ||
            (d->deserialized_state == d->state &&
             d->deserialized_found == d->found))
                return 0;

        d->found = d->deserialized_found;
        device_set_state(d, d->deserialized_state);
        return 0;
}

static void device_catchup(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);

        /* Second, let's update the state with the enumerated state if it's different */
        if (d->enumerated_found == d->found)
                return;

        device_update_found_one(d, d->enumerated_found, DEVICE_FOUND_MASK);
}

static const struct {
        DeviceFound flag;
        const char *name;
} device_found_map[] = {
        { DEVICE_FOUND_UDEV,  "found-udev"  },
        { DEVICE_FOUND_MOUNT, "found-mount" },
        { DEVICE_FOUND_SWAP,  "found-swap"  },
};

static int device_found_to_string_many(DeviceFound flags, char **ret) {
        _cleanup_free_ char *s = NULL;
        unsigned i;

        assert(ret);

        for (i = 0; i < ELEMENTSOF(device_found_map); i++) {
                if (!FLAGS_SET(flags, device_found_map[i].flag))
                        continue;

                if (!strextend_with_separator(&s, ",", device_found_map[i].name, NULL))
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);

        return 0;
}

static int device_found_from_string_many(const char *name, DeviceFound *ret) {
        DeviceFound flags = 0;
        int r;

        assert(ret);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                DeviceFound f = 0;
                unsigned i;

                r = extract_first_word(&name, &word, ",", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                for (i = 0; i < ELEMENTSOF(device_found_map); i++)
                        if (streq(word, device_found_map[i].name)) {
                                f = device_found_map[i].flag;
                                break;
                        }

                if (f == 0)
                        return -EINVAL;

                flags |= f;
        }

        *ret = flags;
        return 0;
}

static int device_serialize(Unit *u, FILE *f, FDSet *fds) {
        _cleanup_free_ char *s = NULL;
        Device *d = DEVICE(u);

        assert(u);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", device_state_to_string(d->state));

        if (device_found_to_string_many(d->found, &s) >= 0)
                (void) serialize_item(f, "found", s);

        return 0;
}

static int device_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Device *d = DEVICE(u);
        int r;

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                DeviceState state;

                state = device_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value, ignoring: %s", value);
                else
                        d->deserialized_state = state;

        } else if (streq(key, "found")) {
                r = device_found_from_string_many(value, &d->deserialized_found);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse found value '%s', ignoring: %m", value);

        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

static void device_dump(Unit *u, FILE *f, const char *prefix) {
        Device *d = DEVICE(u);
        _cleanup_free_ char *s = NULL;

        assert(d);

        (void) device_found_to_string_many(d->found, &s);

        fprintf(f,
                "%sDevice State: %s\n"
                "%sSysfs Path: %s\n"
                "%sFound: %s\n",
                prefix, device_state_to_string(d->state),
                prefix, strna(d->sysfs),
                prefix, strna(s));

        if (!strv_isempty(d->wants_property)) {
                char **i;

                STRV_FOREACH(i, d->wants_property)
                        fprintf(f, "%sudev SYSTEMD_WANTS: %s\n",
                                prefix, *i);
        }
}

_pure_ static UnitActiveState device_active_state(Unit *u) {
        assert(u);

        return state_translation_table[DEVICE(u)->state];
}

_pure_ static const char *device_sub_state_to_string(Unit *u) {
        assert(u);

        return device_state_to_string(DEVICE(u)->state);
}

static int device_update_description(Unit *u, sd_device *dev, const char *path) {
        _cleanup_free_ char *j = NULL;
        const char *model, *label, *desc;
        int r;

        assert(u);
        assert(path);

        desc = path;

        if (dev &&
            (sd_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE", &model) >= 0 ||
             sd_device_get_property_value(dev, "ID_MODEL", &model) >= 0)) {
                desc = model;

                /* Try to concatenate the device model string with a label, if there is one */
                if (sd_device_get_property_value(dev, "ID_FS_LABEL", &label) >= 0 ||
                    sd_device_get_property_value(dev, "ID_PART_ENTRY_NAME", &label) >= 0 ||
                    sd_device_get_property_value(dev, "ID_PART_ENTRY_NUMBER", &label) >= 0) {

                        desc = j = strjoin(model, " ", label);
                        if (!j)
                                return log_oom();
                }
        }

        r = unit_set_description(u, desc);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to set device description: %m");

        return 0;
}

static int device_add_udev_wants(Unit *u, sd_device *dev) {
        _cleanup_strv_free_ char **added = NULL;
        const char *wants, *property;
        Device *d = DEVICE(u);
        int r;

        assert(d);
        assert(dev);

        property = MANAGER_IS_USER(u->manager) ? "SYSTEMD_USER_WANTS" : "SYSTEMD_WANTS";

        r = sd_device_get_property_value(dev, property, &wants);
        if (r < 0)
                return 0;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&wants, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to parse property %s with value %s: %m", property, wants);

                if (unit_name_is_valid(word, UNIT_NAME_TEMPLATE) && d->sysfs) {
                        _cleanup_free_ char *escaped = NULL;

                        /* If the unit name is specified as template, then automatically fill in the sysfs path of the
                         * device as instance name, properly escaped. */

                        r = unit_name_path_escape(d->sysfs, &escaped);
                        if (r < 0)
                                return log_unit_error_errno(u, r, "Failed to escape %s: %m", d->sysfs);

                        r = unit_name_replace_instance(word, escaped, &k);
                        if (r < 0)
                                return log_unit_error_errno(u, r, "Failed to build %s instance of template %s: %m", escaped, word);
                } else {
                        /* If this is not a template, then let's mangle it so, that it becomes a valid unit name. */

                        r = unit_name_mangle(word, UNIT_NAME_MANGLE_WARN, &k);
                        if (r < 0)
                                return log_unit_error_errno(u, r, "Failed to mangle unit name \"%s\": %m", word);
                }

                r = unit_add_dependency_by_name(u, UNIT_WANTS, k, true, UNIT_DEPENDENCY_UDEV);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to add Wants= dependency: %m");

                r = strv_push(&added, k);
                if (r < 0)
                        return log_oom();

                k = NULL;
        }

        if (d->state != DEVICE_DEAD) {
                char **i;

                /* So here's a special hack, to compensate for the fact that the udev database's reload cycles are not
                 * synchronized with our own reload cycles: when we detect that the SYSTEMD_WANTS property of a device
                 * changes while the device unit is already up, let's manually trigger any new units listed in it not
                 * seen before. This typically happens during the boot-time switch root transition, as udev devices
                 * will generally already be up in the initrd, but SYSTEMD_WANTS properties get then added through udev
                 * rules only available on the host system, and thus only when the initial udev coldplug trigger runs.
                 *
                 * We do this only if the device has been up already when we parse this, as otherwise the usual
                 * dependency logic that is run from the dead → plugged transition will trigger these deps. */

                STRV_FOREACH(i, added) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                        if (strv_contains(d->wants_property, *i)) /* Was this unit already listed before? */
                                continue;

                        r = manager_add_job_by_name(u->manager, JOB_START, *i, JOB_FAIL, NULL, &error, NULL);
                        if (r < 0)
                                log_unit_warning_errno(u, r, "Failed to enqueue SYSTEMD_WANTS= job, ignoring: %s", bus_error_message(&error, r));
                }
        }

        strv_free(d->wants_property);
        d->wants_property = TAKE_PTR(added);

        return 0;
}

static bool device_is_bound_by_mounts(Device *d, sd_device *dev) {
        const char *bound_by;
        int r;

        assert(d);
        assert(dev);

        if (sd_device_get_property_value(dev, "SYSTEMD_MOUNT_DEVICE_BOUND", &bound_by) >= 0) {
                r = parse_boolean(bound_by);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to parse SYSTEMD_MOUNT_DEVICE_BOUND='%s' udev property, ignoring: %m", bound_by);

                d->bind_mounts = r > 0;
        } else
                d->bind_mounts = false;

        return d->bind_mounts;
}

static void device_upgrade_mount_deps(Unit *u) {
        Unit *other;
        Iterator i;
        void *v;
        int r;

        /* Let's upgrade Requires= to BindsTo= on us. (Used when SYSTEMD_MOUNT_DEVICE_BOUND is set) */

        HASHMAP_FOREACH_KEY(v, other, u->dependencies[UNIT_REQUIRED_BY], i) {
                if (other->type != UNIT_MOUNT)
                        continue;

                r = unit_add_dependency(other, UNIT_BINDS_TO, u, true, UNIT_DEPENDENCY_UDEV);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to add BindsTo= dependency between device and mount unit, ignoring: %m");
        }
}

static int device_setup_unit(Manager *m, sd_device *dev, const char *path, bool main) {
        _cleanup_free_ char *e = NULL;
        const char *sysfs = NULL;
        Unit *u = NULL;
        bool delete;
        int r;

        assert(m);
        assert(path);

        if (dev) {
                r = sd_device_get_syspath(dev, &sysfs);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Couldn't get syspath from device, ignoring: %m");
                        return 0;
                }
        }

        r = unit_name_from_path(path, ".device", &e);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to generate unit name from device path: %m");

        u = manager_get_unit(m, e);
        if (u) {
                /* The device unit can still be present even if the device was unplugged: a mount unit can reference it
                 * hence preventing the GC to have garbaged it. That's desired since the device unit may have a
                 * dependency on the mount unit which was added during the loading of the later. When the device is
                 * plugged the sysfs might not be initialized yet, as we serialize the device's state but do not
                 * serialize the sysfs path across reloads/reexecs. Hence, when coming back from a reload/restart we
                 * might have the state valid, but not the sysfs path. Hence, let's filter out conflicting devices, but
                 * let's accept devices in any state with no sysfs path set. */

                if (DEVICE(u)->state == DEVICE_PLUGGED &&
                    DEVICE(u)->sysfs &&
                    sysfs &&
                    !path_equal(DEVICE(u)->sysfs, sysfs)) {
                        log_unit_debug(u, "Device %s appeared twice with different sysfs paths %s and %s, ignoring the latter.",
                                       e, DEVICE(u)->sysfs, sysfs);
                        return -EEXIST;
                }

                delete = false;

                /* Let's remove all dependencies generated due to udev properties. We'll re-add whatever is configured
                 * now below. */
                unit_remove_dependencies(u, UNIT_DEPENDENCY_UDEV);
        } else {
                delete = true;

                r = unit_new_for_name(m, sizeof(Device), e, &u);
                if (r < 0) {
                        log_device_error_errno(dev, r, "Failed to allocate device unit %s: %m", e);
                        goto fail;
                }

                unit_add_to_load_queue(u);
        }

        /* If this was created via some dependency and has not actually been seen yet ->sysfs will not be
         * initialized. Hence initialize it if necessary. */
        if (sysfs) {
                r = device_set_sysfs(DEVICE(u), sysfs);
                if (r < 0) {
                        log_unit_error_errno(u, r, "Failed to set sysfs path %s: %m", sysfs);
                        goto fail;
                }

                /* The additional systemd udev properties we only interpret for the main object */
                if (main)
                        (void) device_add_udev_wants(u, dev);
        }

        (void) device_update_description(u, dev, path);

        /* So the user wants the mount units to be bound to the device but a mount unit might has been seen by systemd
         * before the device appears on its radar. In this case the device unit is partially initialized and includes
         * the deps on the mount unit but at that time the "bind mounts" flag wasn't not present. Fix this up now. */
        if (dev && device_is_bound_by_mounts(DEVICE(u), dev))
                device_upgrade_mount_deps(u);

        /* Note that this won't dispatch the load queue, the caller has to do that if needed and appropriate */
        unit_add_to_dbus_queue(u);

        return 0;

fail:
        if (delete)
                unit_free(u);

        return r;
}

static int device_process_new(Manager *m, sd_device *dev) {
        const char *sysfs, *dn, *alias;
        dev_t devnum;
        int r;

        assert(m);

        if (sd_device_get_syspath(dev, &sysfs) < 0)
                return 0;

        /* Add the main unit named after the sysfs path */
        r = device_setup_unit(m, dev, sysfs, true);
        if (r < 0)
                return r;

        /* Add an additional unit for the device node */
        if (sd_device_get_devname(dev, &dn) >= 0)
                (void) device_setup_unit(m, dev, dn, false);

        /* Add additional units for all symlinks */
        if (sd_device_get_devnum(dev, &devnum) >= 0) {
                const char *p;

                FOREACH_DEVICE_DEVLINK(dev, p) {
                        struct stat st;

                        if (PATH_STARTSWITH_SET(p, "/dev/block/", "/dev/char/"))
                                continue;

                        /* Verify that the symlink in the FS actually belongs
                         * to this device. This is useful to deal with
                         * conflicting devices, e.g. when two disks want the
                         * same /dev/disk/by-label/xxx link because they have
                         * the same label. We want to make sure that the same
                         * device that won the symlink wins in systemd, so we
                         * check the device node major/minor */
                        if (stat(p, &st) >= 0 &&
                            ((!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode)) ||
                             st.st_rdev != devnum))
                                continue;

                        (void) device_setup_unit(m, dev, p, false);
                }
        }

        /* Add additional units for all explicitly configured aliases */
        if (sd_device_get_property_value(dev, "SYSTEMD_ALIAS", &alias) < 0)
                return 0;

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&alias, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_device_warning_errno(dev, r, "Failed to parse SYSTEMD_ALIAS property: %m");

                if (!path_is_absolute(word))
                        log_device_warning(dev, "SYSTEMD_ALIAS is not an absolute path, ignoring: %s", word);
                else if (!path_is_normalized(word))
                        log_device_warning(dev, "SYSTEMD_ALIAS is not a normalized path, ignoring: %s", word);
                else
                        (void) device_setup_unit(m, dev, word, false);
        }

        return 0;
}

static void device_found_changed(Device *d, DeviceFound previous, DeviceFound now) {
        assert(d);

        /* Didn't exist before, but does now? if so, generate a new invocation ID for it */
        if (previous == DEVICE_NOT_FOUND && now != DEVICE_NOT_FOUND)
                (void) unit_acquire_invocation_id(UNIT(d));

        if (FLAGS_SET(now, DEVICE_FOUND_UDEV))
                /* When the device is known to udev we consider it plugged. */
                device_set_state(d, DEVICE_PLUGGED);
        else if (now != DEVICE_NOT_FOUND && !FLAGS_SET(previous, DEVICE_FOUND_UDEV))
                /* If the device has not been seen by udev yet, but is now referenced by the kernel, then we assume the
                 * kernel knows it now, and udev might soon too. */
                device_set_state(d, DEVICE_TENTATIVE);
        else
                /* If nobody sees the device, or if the device was previously seen by udev and now is only referenced
                 * from the kernel, then we consider the device is gone, the kernel just hasn't noticed it yet. */
                device_set_state(d, DEVICE_DEAD);
}

static void device_update_found_one(Device *d, DeviceFound found, DeviceFound mask) {
        Manager *m;

        assert(d);

        m = UNIT(d)->manager;

        if (MANAGER_IS_RUNNING(m) && (m->honor_device_enumeration || MANAGER_IS_USER(m))) {
                DeviceFound n, previous;

                /* When we are already running, then apply the new mask right-away, and trigger state changes
                 * right-away */

                n = (d->found & ~mask) | (found & mask);
                if (n == d->found)
                        return;

                previous = d->found;
                d->found = n;

                device_found_changed(d, previous, n);
        } else
                /* We aren't running yet, let's apply the new mask to the shadow variable instead, which we'll apply as
                 * soon as we catch-up with the state. */
                d->enumerated_found = (d->enumerated_found & ~mask) | (found & mask);
}

static void device_update_found_by_sysfs(Manager *m, const char *sysfs, DeviceFound found, DeviceFound mask) {
        Device *d, *l, *n;

        assert(m);
        assert(sysfs);

        if (mask == 0)
                return;

        l = hashmap_get(m->devices_by_sysfs, sysfs);
        LIST_FOREACH_SAFE(same_sysfs, d, n, l)
                device_update_found_one(d, found, mask);
}

static int device_update_found_by_name(Manager *m, const char *path, DeviceFound found, DeviceFound mask) {
        _cleanup_free_ char *e = NULL;
        Unit *u;
        int r;

        assert(m);
        assert(path);

        if (mask == 0)
                return 0;

        r = unit_name_from_path(path, ".device", &e);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name from device path: %m");

        u = manager_get_unit(m, e);
        if (!u)
                return 0;

        device_update_found_one(DEVICE(u), found, mask);
        return 0;
}

static bool device_is_ready(sd_device *dev) {
        const char *ready;

        assert(dev);

        if (device_is_renaming(dev) > 0)
                return false;

        if (sd_device_get_property_value(dev, "SYSTEMD_READY", &ready) < 0)
                return true;

        return parse_boolean(ready) != 0;
}

static Unit *device_following(Unit *u) {
        Device *d = DEVICE(u);
        Device *other, *first = NULL;

        assert(d);

        if (startswith(u->id, "sys-"))
                return NULL;

        /* Make everybody follow the unit that's named after the sysfs path */
        LIST_FOREACH_AFTER(same_sysfs, other, d)
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

        LIST_FOREACH_BEFORE(same_sysfs, other, d) {
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

                first = other;
        }

        return UNIT(first);
}

static int device_following_set(Unit *u, Set **_set) {
        Device *d = DEVICE(u), *other;
        _cleanup_set_free_ Set *set = NULL;
        int r;

        assert(d);
        assert(_set);

        if (LIST_JUST_US(same_sysfs, d)) {
                *_set = NULL;
                return 0;
        }

        set = set_new(NULL);
        if (!set)
                return -ENOMEM;

        LIST_FOREACH_AFTER(same_sysfs, other, d) {
                r = set_put(set, other);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH_BEFORE(same_sysfs, other, d) {
                r = set_put(set, other);
                if (r < 0)
                        return r;
        }

        *_set = TAKE_PTR(set);
        return 1;
}

static void device_shutdown(Manager *m) {
        assert(m);

        m->device_monitor = sd_device_monitor_unref(m->device_monitor);
        m->devices_by_sysfs = hashmap_free(m->devices_by_sysfs);
}

static void device_enumerate(Manager *m) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int r;

        assert(m);

        if (!m->device_monitor) {
                r = sd_device_monitor_new(&m->device_monitor);
                if (r < 0) {
                        log_error_errno(r, "Failed to allocate device monitor: %m");
                        goto fail;
                }

                /* This will fail if we are unprivileged, but that
                 * should not matter much, as user instances won't run
                 * during boot. */
                (void) sd_device_monitor_set_receive_buffer_size(m->device_monitor, 128*1024*1024);

                r = sd_device_monitor_filter_add_match_tag(m->device_monitor, "systemd");
                if (r < 0) {
                        log_error_errno(r, "Failed to add udev tag match: %m");
                        goto fail;
                }

                r = sd_device_monitor_attach_event(m->device_monitor, m->event);
                if (r < 0) {
                        log_error_errno(r, "Failed to attach event to device monitor: %m");
                        goto fail;
                }

                r = sd_device_monitor_start(m->device_monitor, device_dispatch_io, m);
                if (r < 0) {
                        log_error_errno(r, "Failed to start device monitor: %m");
                        goto fail;
                }
        }

        r = sd_device_enumerator_new(&e);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate device enumerator: %m");
                goto fail;
        }

        r = sd_device_enumerator_add_match_tag(e, "systemd");
        if (r < 0) {
                log_error_errno(r, "Failed to set tag for device enumeration: %m");
                goto fail;
        }

        FOREACH_DEVICE(e, dev) {
                const char *sysfs;

                if (!device_is_ready(dev))
                        continue;

                (void) device_process_new(m, dev);

                if (sd_device_get_syspath(dev, &sysfs) < 0)
                        continue;

                device_update_found_by_sysfs(m, sysfs, DEVICE_FOUND_UDEV, DEVICE_FOUND_UDEV);
        }

        return;

fail:
        device_shutdown(m);
}

static void device_propagate_reload_by_sysfs(Manager *m, const char *sysfs) {
        Device *d, *l, *n;
        int r;

        assert(m);
        assert(sysfs);

        l = hashmap_get(m->devices_by_sysfs, sysfs);
        LIST_FOREACH_SAFE(same_sysfs, d, n, l) {
                if (d->state == DEVICE_DEAD)
                        continue;

                r = manager_propagate_reload(m, UNIT(d), JOB_REPLACE, NULL);
                if (r < 0)
                        log_warning_errno(r, "Failed to propagate reload, ignoring: %m");
        }
}

static int device_dispatch_io(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        Manager *m = userdata;
        DeviceAction action;
        const char *sysfs;
        int r;

        assert(m);
        assert(dev);

        r = sd_device_get_syspath(dev, &sysfs);
        if (r < 0) {
                log_device_error_errno(dev, r, "Failed to get device sys path: %m");
                return 0;
        }

        r = device_get_action(dev, &action);
        if (r < 0) {
                log_device_error_errno(dev, r, "Failed to get udev action: %m");
                return 0;
        }

        if (action == DEVICE_ACTION_CHANGE)
                device_propagate_reload_by_sysfs(m, sysfs);

        /* A change event can signal that a device is becoming ready, in particular if
         * the device is using the SYSTEMD_READY logic in udev
         * so we need to reach the else block of the following if, even for change events */
        if (action == DEVICE_ACTION_REMOVE) {
                r = swap_process_device_remove(m, dev);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to process swap device remove event, ignoring: %m");

                /* If we get notified that a device was removed by
                 * udev, then it's completely gone, hence unset all
                 * found bits */
                device_update_found_by_sysfs(m, sysfs, 0, DEVICE_FOUND_UDEV|DEVICE_FOUND_MOUNT|DEVICE_FOUND_SWAP);

        } else if (device_is_ready(dev)) {

                (void) device_process_new(m, dev);

                r = swap_process_device_new(m, dev);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to process swap device new event, ignoring: %m");

                manager_dispatch_load_queue(m);

                /* The device is found now, set the udev found bit */
                device_update_found_by_sysfs(m, sysfs, DEVICE_FOUND_UDEV, DEVICE_FOUND_UDEV);

        } else {
                /* The device is nominally around, but not ready for
                 * us. Hence unset the udev bit, but leave the rest
                 * around. */

                device_update_found_by_sysfs(m, sysfs, 0, DEVICE_FOUND_UDEV);
        }

        return 0;
}

static bool device_supported(void) {
        static int read_only = -1;

        /* If /sys is read-only we don't support device units, and any
         * attempts to start one should fail immediately. */

        if (read_only < 0)
                read_only = path_is_read_only_fs("/sys");

        return read_only <= 0;
}

static int validate_node(Manager *m, const char *node, sd_device **ret) {
        struct stat st;
        int r;

        assert(m);
        assert(node);
        assert(ret);

        /* Validates a device node that showed up in /proc/swaps or /proc/self/mountinfo if it makes sense for us to
         * track. Note that this validator is fine within missing device nodes, but not with badly set up ones! */

        if (!path_startswith(node, "/dev")) {
                *ret = NULL;
                return 0; /* bad! */
        }

        if (stat(node, &st) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to stat() device node file %s: %m", node);

                *ret = NULL;
                return 1; /* good! (though missing) */

        } else {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                r = device_new_from_stat_rdev(&dev, &st);
                if (r == -ENOENT) {
                        *ret = NULL;
                        return 1; /* good! (though missing) */
                } else if (r == -ENOTTY) {
                        *ret = NULL;
                        return 0; /* bad! (not a device node but some other kind of file system node) */
                } else if (r < 0)
                        return log_error_errno(r, "Failed to get udev device from devnum %u:%u: %m", major(st.st_rdev), minor(st.st_rdev));

                *ret = TAKE_PTR(dev);
                return 1; /* good! */
        }
}

void device_found_node(Manager *m, const char *node, DeviceFound found, DeviceFound mask) {
        int r;

        assert(m);
        assert(node);

        if (!device_supported())
                return;

        if (mask == 0)
                return;

        /* This is called whenever we find a device referenced in /proc/swaps or /proc/self/mounts. Such a device might
         * be mounted/enabled at a time where udev has not finished probing it yet, and we thus haven't learned about
         * it yet. In this case we will set the device unit to "tentative" state.
         *
         * This takes a pair of DeviceFound flags parameters. The 'mask' parameter is a bit mask that indicates which
         * bits of 'found' to copy into the per-device DeviceFound flags field. Thus, this function may be used to set
         * and unset individual bits in a single call, while merging partially with previous state. */

        if ((found & mask) != 0) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                /* If the device is known in the kernel and newly appeared, then we'll create a device unit for it,
                 * under the name referenced in /proc/swaps or /proc/self/mountinfo. But first, let's validate if
                 * everything is alright with the device node. */

                r = validate_node(m, node, &dev);
                if (r <= 0)
                        return; /* Don't create a device unit for this if the device node is borked. */

                (void) device_setup_unit(m, dev, node, false);
        }

        /* Update the device unit's state, should it exist */
        (void) device_update_found_by_name(m, node, found, mask);
}

bool device_shall_be_bound_by(Unit *device, Unit *u) {
        assert(device);
        assert(u);

        if (u->type != UNIT_MOUNT)
                return false;

        return DEVICE(device)->bind_mounts;
}

const UnitVTable device_vtable = {
        .object_size = sizeof(Device),
        .sections =
                "Unit\0"
                "Device\0"
                "Install\0",

        .gc_jobs = true,

        .init = device_init,
        .done = device_done,
        .load = device_load,

        .coldplug = device_coldplug,
        .catchup = device_catchup,

        .serialize = device_serialize,
        .deserialize_item = device_deserialize_item,

        .dump = device_dump,

        .active_state = device_active_state,
        .sub_state_to_string = device_sub_state_to_string,

        .bus_vtable = bus_device_vtable,

        .following = device_following,
        .following_set = device_following_set,

        .enumerate = device_enumerate,
        .shutdown = device_shutdown,
        .supported = device_supported,

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
