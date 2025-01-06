/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/epoll.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "dbus-device.h"
#include "dbus-unit.h"
#include "device-private.h"
#include "device-util.h"
#include "device.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "ratelimit.h"
#include "serialize.h"
#include "stat-util.h"
#include "string-util.h"
#include "swap.h"
#include "udev-util.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD]      = UNIT_INACTIVE,
        [DEVICE_TENTATIVE] = UNIT_ACTIVATING,
        [DEVICE_PLUGGED]   = UNIT_ACTIVE,
};

static int device_dispatch_io(sd_device_monitor *monitor, sd_device *dev, void *userdata);

static int device_by_path(Manager *m, const char *path, Unit **ret) {
        _cleanup_free_ char *e = NULL;
        Unit *u;
        int r;

        assert(m);
        assert(path);

        r = unit_name_from_path(path, ".device", &e);
        if (r < 0)
                return r;

        u = manager_get_unit(m, e);
        if (!u)
                return -ENOENT;

        if (ret)
                *ret = u;
        return 0;
}

static void device_unset_sysfs(Device *d) {
        assert(d);

        if (!d->sysfs)
                return;

        /* Remove this unit from the chain of devices which share the same sysfs path. */

        Hashmap *devices = ASSERT_PTR(UNIT(d)->manager->devices_by_sysfs);

        if (d->same_sysfs_prev)
                /* If this is not the first unit, then simply remove this unit. */
                d->same_sysfs_prev->same_sysfs_next = d->same_sysfs_next;
        else if (d->same_sysfs_next)
                /* If this is the first unit, replace with the next unit. */
                assert_se(hashmap_replace(devices, d->same_sysfs_next->sysfs, d->same_sysfs_next) >= 0);
        else
                /* Otherwise, remove the entry. */
                hashmap_remove(devices, d->sysfs);

        if (d->same_sysfs_next)
                d->same_sysfs_next->same_sysfs_prev = d->same_sysfs_prev;

        d->same_sysfs_prev = d->same_sysfs_next = NULL;

        d->sysfs = mfree(d->sysfs);
}

static int device_set_sysfs(Device *d, const char *sysfs) {
        Unit *u = UNIT(ASSERT_PTR(d));
        int r;

        assert(sysfs);

        if (path_equal(d->sysfs, sysfs))
                return 0;

        Hashmap **devices = &u->manager->devices_by_sysfs;

        r = hashmap_ensure_allocated(devices, &path_hash_ops);
        if (r < 0)
                return r;

        _cleanup_free_ char *copy = strdup(sysfs);
        if (!copy)
                return -ENOMEM;

        device_unset_sysfs(d);

        Device *first = hashmap_get(*devices, sysfs);
        LIST_PREPEND(same_sysfs, first, d);

        r = hashmap_replace(*devices, copy, first);
        if (r < 0) {
                LIST_REMOVE(same_sysfs, first, d);
                return r;
        }

        d->sysfs = TAKE_PTR(copy);
        unit_add_to_dbus_queue(u);

        return 0;
}

static void device_init(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u));

        assert(u->load_state == UNIT_STUB);

        /* In contrast to all other unit types we timeout jobs waiting
         * for devices by default. This is because they otherwise wait
         * indefinitely for plugged in devices, something which cannot
         * happen for the other units since their operations time out
         * anyway. */
        u->job_running_timeout = u->manager->defaults.device_timeout_usec;

        u->ignore_on_isolate = true;

        d->deserialized_state = _DEVICE_STATE_INVALID;
}

static void device_done(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u));

        device_unset_sysfs(d);
        d->deserialized_sysfs = mfree(d->deserialized_sysfs);
        d->wants_property = strv_free(d->wants_property);
        d->path = mfree(d->path);
}

static int device_load(Unit *u) {
        int r;

        r = unit_load_fragment_and_dropin(u, false);
        if (r < 0)
                return r;

        if (!u->description) {
                /* Generate a description based on the path, to be used until the device is initialized
                   properly */
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

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state], /* reload_success = */ true);
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
        assert(d);

        if (MANAGER_IS_RUNNING(UNIT(d)->manager)) {
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
        Device *l;

        assert(m);
        assert(sysfs);

        if (mask == 0)
                return;

        l = hashmap_get(m->devices_by_sysfs, sysfs);
        LIST_FOREACH(same_sysfs, d, l)
                device_update_found_one(d, found, mask);
}

static void device_update_found_by_name(Manager *m, const char *path, DeviceFound found, DeviceFound mask) {
        Unit *u;

        assert(m);
        assert(path);

        if (mask == 0)
                return;

        if (device_by_path(m, path, &u) < 0)
                return;

        device_update_found_one(DEVICE(u), found, mask);
}

static int device_coldplug(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u));

        assert(d->state == DEVICE_DEAD);

        /* First, let's put the deserialized state and found mask into effect, if we have it. */
        if (d->deserialized_state < 0)
                return 0;

        Manager *m = u->manager;
        DeviceFound found = d->deserialized_found;
        DeviceState state = d->deserialized_state;

        /* On initial boot, switch-root, reload, reexecute, the following happen:
         * 1. MANAGER_IS_RUNNING() == false
         * 2. enumerate devices: manager_enumerate() -> device_enumerate()
         *    Device.enumerated_found is set.
         * 3. deserialize devices: manager_deserialize() -> device_deserialize_item()
         *    Device.deserialize_state and Device.deserialized_found are set.
         * 4. coldplug devices: manager_coldplug() -> device_coldplug()
         *    deserialized properties are copied to the main properties.
         * 5. MANAGER_IS_RUNNING() == true: manager_ready()
         * 6. catchup devices: manager_catchup() -> device_catchup()
         *    Device.enumerated_found is applied to Device.found, and state is updated based on that.
         *
         * Notes:
         * - On initial boot, no udev database exists. Hence, no devices are enumerated in the step 2.
         *   Also, there is no deserialized device. Device units are (a) generated based on dependencies of
         *   other units, or (b) generated when uevents are received.
         *
         * - On switch-root, the udev database may be cleared, except for devices with sticky bit, i.e.
         *   OPTIONS="db_persist". Hence, almost no devices are enumerated in the step 2. However, in
         *   general, we have several serialized devices. So, DEVICE_FOUND_UDEV bit in the
         *   Device.deserialized_found must be ignored, as udev rules in initrd and the main system are often
         *   different. If the deserialized state is DEVICE_PLUGGED, we need to downgrade it to
         *   DEVICE_TENTATIVE. Unlike the other starting mode, MANAGER_IS_SWITCHING_ROOT() is true when
         *   device_coldplug() and device_catchup() are called. Hence, let's conditionalize the operations by
         *   using the flag. After switch-root, systemd-udevd will (re-)process all devices, and the
         *   Device.found and Device.state will be adjusted.
         *
         * - On reload or reexecute, we can trust Device.enumerated_found, Device.deserialized_found, and
         *   Device.deserialized_state. Of course, deserialized parameters may be outdated, but the unit
         *   state can be adjusted later by device_catchup() or uevents. */

        if (MANAGER_IS_SWITCHING_ROOT(m) &&
            !FLAGS_SET(d->enumerated_found, DEVICE_FOUND_UDEV)) {

                /* The device has not been enumerated. On switching-root, such situation is natural. See the
                 * above comment. To prevent problematic state transition active → dead → active, let's
                 * drop the DEVICE_FOUND_UDEV flag and downgrade state to DEVICE_TENTATIVE(activating). See
                 * issue #12953 and #23208. */
                found &= ~DEVICE_FOUND_UDEV;
                if (state == DEVICE_PLUGGED)
                        state = DEVICE_TENTATIVE;

                /* Also check the validity of the device syspath. Without this check, if the device was
                 * removed while switching root, it would never go to inactive state, as both Device.found
                 * and Device.enumerated_found do not have the DEVICE_FOUND_UDEV flag, so device_catchup() in
                 * device_update_found_one() does nothing in most cases. See issue #25106. Note that the
                 * syspath field is only serialized when systemd is sufficiently new and the device has been
                 * already processed by udevd. */
                if (d->deserialized_sysfs) {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        if (sd_device_new_from_syspath(&dev, d->deserialized_sysfs) < 0)
                                state = DEVICE_DEAD;
                }
        }

        if (d->found == found && d->state == state)
                return 0;

        d->found = found;
        device_set_state(d, state);
        return 0;
}

static void device_catchup(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u));

        /* Second, let's update the state with the enumerated state */

        /* If Device.found (set from Device.deserialized_found) does not have DEVICE_FOUND_UDEV, and the
         * device has not been processed by udevd while enumeration, it indicates the unit was never active
         * before reexecution, hence we can safely drop the flag from Device.enumerated_found. The device
         * will be set up later when udev finishes processing (see also comment in
         * device_setup_devlink_unit_one()).
         *
         * NB: 💣💣💣 If Device.found already contains udev, i.e. the unit was fully ready before
         * reexecution, do not unset the flag. Otherwise, e.g. if systemd-udev-trigger.service is started
         * just before reexec, reload, and so on, devices being reprocessed (carrying ID_PROCESSING=1
         * property) on enumeration and will enter dead state. See issue #35329. */
        if (!FLAGS_SET(d->found, DEVICE_FOUND_UDEV) && !d->processed)
                d->enumerated_found &= ~DEVICE_FOUND_UDEV;

        device_update_found_one(d, d->enumerated_found, _DEVICE_FOUND_MASK);
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

        assert(flags >= 0);
        assert(ret);

        FOREACH_ELEMENT(i, device_found_map) {
                if (!FLAGS_SET(flags, i->flag))
                        continue;

                if (!strextend_with_separator(&s, ",", i->name))
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

                r = extract_first_word(&name, &word, ",", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                FOREACH_ELEMENT(i, device_found_map)
                        if (streq(word, i->name)) {
                                f = i->flag;
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
        Device *d = ASSERT_PTR(DEVICE(u));
        _cleanup_free_ char *s = NULL;

        assert(f);
        assert(fds);

        if (d->sysfs)
                (void) serialize_item(f, "sysfs", d->sysfs);

        if (d->path)
                (void) serialize_item(f, "path", d->path);

        (void) serialize_item(f, "state", device_state_to_string(d->state));

        if (device_found_to_string_many(d->found, &s) >= 0)
                (void) serialize_item(f, "found", s);

        return 0;
}

static int device_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Device *d = ASSERT_PTR(DEVICE(u));
        int r;

        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "sysfs")) {
                if (!d->deserialized_sysfs) {
                        d->deserialized_sysfs = strdup(value);
                        if (!d->deserialized_sysfs)
                                log_oom_debug();
                }

        } else if (streq(key, "path")) {
                if (!d->path) {
                        d->path = strdup(value);
                        if (!d->path)
                                log_oom_debug();
                }

        } else if (streq(key, "state")) {
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
        Device *d = ASSERT_PTR(DEVICE(u));
        _cleanup_free_ char *s = NULL;

        assert(f);
        assert(prefix);

        (void) device_found_to_string_many(d->found, &s);

        fprintf(f,
                "%sDevice State: %s\n"
                "%sDevice Path: %s\n"
                "%sSysfs Path: %s\n"
                "%sFound: %s\n",
                prefix, device_state_to_string(d->state),
                prefix, strna(d->path),
                prefix, strna(d->sysfs),
                prefix, strna(s));

        STRV_FOREACH(i, d->wants_property)
                fprintf(f, "%sudev SYSTEMD_WANTS: %s\n",
                        prefix, *i);
}

static UnitActiveState device_active_state(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u));

        return state_translation_table[d->state];
}

static const char *device_sub_state_to_string(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u));

        return device_state_to_string(d->state);
}

static int device_update_description(Unit *u, sd_device *dev, const char *path) {
        _cleanup_free_ char *j = NULL;
        const char *model, *label, *desc;
        int r;

        assert(u);
        assert(path);

        desc = path;

        if (dev && device_get_model_string(dev, &model) >= 0) {
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
        Device *d = ASSERT_PTR(DEVICE(u));
        _cleanup_strv_free_ char **added = NULL;
        const char *wants, *property;
        int r;

        assert(dev);

        property = MANAGER_IS_USER(u->manager) ? "SYSTEMD_USER_WANTS" : "SYSTEMD_WANTS";

        r = sd_device_get_property_value(dev, property, &wants);
        if (r < 0)
                return 0;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&wants, &word, NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE);
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

                r = strv_consume(&added, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }

        if (d->state != DEVICE_DEAD)
                /* So here's a special hack, to compensate for the fact that the udev database's reload cycles are not
                 * synchronized with our own reload cycles: when we detect that the SYSTEMD_WANTS property of a device
                 * changes while the device unit is already up, let's skip to trigger units that were already listed
                 * and are active, and start units otherwise. This typically happens during the boot-time switch root
                 * transition, as udev devices will generally already be up in the initrd, but SYSTEMD_WANTS properties
                 * get then added through udev rules only available on the host system, and thus only when the initial
                 * udev coldplug trigger runs.
                 *
                 * We do this only if the device has been up already when we parse this, as otherwise the usual
                 * dependency logic that is run from the dead → plugged transition will trigger these deps. */
                STRV_FOREACH(i, added) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                        if (strv_contains(d->wants_property, *i)) {
                                Unit *v;

                                v = manager_get_unit(u->manager, *i);
                                if (v && UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(v)))
                                        continue; /* The unit was already listed and is running. */
                        }

                        r = manager_add_job_by_name(u->manager, JOB_START, *i, JOB_FAIL, NULL, &error, NULL);
                        if (r < 0)
                                log_unit_full_errno(u, sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT) ? LOG_DEBUG : LOG_WARNING, r,
                                                    "Failed to enqueue %s job, ignoring: %s", property, bus_error_message(&error, r));
                }

        return strv_free_and_replace(d->wants_property, added);
}

static bool device_is_bound_by_mounts(Device *d, sd_device *dev) {
        int r;

        assert(d);
        assert(dev);

        r = device_get_property_bool(dev, "SYSTEMD_MOUNT_DEVICE_BOUND");
        if (r < 0 && r != -ENOENT)
                log_device_warning_errno(dev, r, "Failed to parse SYSTEMD_MOUNT_DEVICE_BOUND= udev property, ignoring: %m");

        d->bind_mounts = r > 0;

        return d->bind_mounts;
}

static void device_upgrade_mount_deps(Unit *u) {
        Unit *other;
        void *v;
        int r;

        /* Let's upgrade Requires= to BindsTo= on us. (Used when SYSTEMD_MOUNT_DEVICE_BOUND is set) */

        assert(u);

        HASHMAP_FOREACH_KEY(v, other, unit_get_dependencies(u, UNIT_REQUIRED_BY)) {
                if (other->type != UNIT_MOUNT)
                        continue;

                r = unit_add_dependency(other, UNIT_BINDS_TO, u, true, UNIT_DEPENDENCY_UDEV);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to add BindsTo= dependency between device and mount unit, ignoring: %m");
        }
}

static int device_setup_unit(Manager *m, sd_device *dev, const char *path, bool main, Set **units) {
        _cleanup_(unit_freep) Unit *new_unit = NULL;
        _cleanup_free_ char *e = NULL;
        const char *sysfs = NULL;
        Unit *u;
        int r;

        assert(m);
        assert(path);

        if (dev) {
                r = sd_device_get_syspath(dev, &sysfs);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Couldn't get syspath from device, ignoring: %m");
        }

        r = unit_name_from_path(path, ".device", &e);
        if (r < 0)
                return log_struct_errno(
                                LOG_WARNING, r,
                                "MESSAGE_ID=" SD_MESSAGE_DEVICE_PATH_NOT_SUITABLE_STR,
                                "DEVICE=%s", path,
                                LOG_MESSAGE("Failed to generate valid unit name from device path '%s', ignoring device: %m",
                                            path));

        u = manager_get_unit(m, e);
        if (u) {
                /* The device unit can still be present even if the device was unplugged: a mount unit can reference it
                 * hence preventing the GC to have garbaged it. That's desired since the device unit may have a
                 * dependency on the mount unit which was added during the loading of the later. When the device is
                 * plugged the sysfs might not be initialized yet, as we serialize the device's state but do not
                 * serialize the sysfs path across reloads/reexecs. Hence, when coming back from a reload/restart we
                 * might have the state valid, but not the sysfs path. Also, there is another possibility; when multiple
                 * devices have the same devlink (e.g. /dev/disk/by-uuid/xxxx), adding/updating/removing one of the
                 * device causes syspath change. Hence, let's always update sysfs path. */

                /* Let's remove all dependencies generated due to udev properties. We'll re-add whatever is configured
                 * now below. */
                unit_remove_dependencies(u, UNIT_DEPENDENCY_UDEV);

        } else {
                r = unit_new_for_name(m, sizeof(Device), e, &new_unit);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to allocate device unit %s: %m", e);

                u = new_unit;

                unit_add_to_load_queue(u);
        }

        Device *d = ASSERT_PTR(DEVICE(u));

        if (!d->path) {
                d->path = strdup(path);
                if (!d->path)
                        return log_oom();
        }

        /* If this was created via some dependency and has not actually been seen yet ->sysfs will not be
         * initialized. Hence initialize it if necessary. */
        if (sysfs) {
                r = device_set_sysfs(d, sysfs);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to set sysfs path %s: %m", sysfs);

                /* The additional systemd udev properties we only interpret for the main object */
                if (main)
                        (void) device_add_udev_wants(u, dev);
        }

        (void) device_update_description(u, dev, path);

        /* So the user wants the mount units to be bound to the device but a mount unit might has been seen
         * by systemd before the device appears on its radar. In this case the device unit is partially
         * initialized and includes the deps on the mount unit but at that time the "bind mounts" flag wasn't
         * present. Fix this up now. */
        if (dev && device_is_bound_by_mounts(d, dev))
                device_upgrade_mount_deps(u);

        if (units) {
                r = set_ensure_put(units, NULL, d);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to store unit: %m");
        }

        TAKE_PTR(new_unit);
        return 0;
}

static bool device_is_ready(sd_device *dev) {
        int r;

        assert(dev);

        if (device_for_action(dev, SD_DEVICE_REMOVE))
                return false;

        r = device_is_renaming(dev);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to check if device is renaming, assuming device is not renaming: %m");
        if (r > 0) {
                log_device_debug(dev, "Device busy: device is renaming");
                return false;
        }

        /* Is it really tagged as 'systemd' right now? */
        r = sd_device_has_current_tag(dev, "systemd");
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to check if device has \"systemd\" tag, assuming device is not tagged with \"systemd\": %m");
        if (r == 0)
                log_device_debug(dev, "Device busy: device is not tagged with \"systemd\"");
        if (r <= 0)
                return false;

        r = device_get_property_bool(dev, "SYSTEMD_READY");
        if (r < 0 && r != -ENOENT)
                log_device_warning_errno(dev, r, "Failed to get device SYSTEMD_READY property, assuming device does not have \"SYSTEMD_READY\" property: %m");
        if (r == 0)
                log_device_debug(dev, "Device busy: SYSTEMD_READY property from device is false");

        return r != 0;
}

static int device_setup_devlink_unit_one(Manager *m, const char *devlink, Set **ready_units, Set **not_ready_units) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        Unit *u;

        assert(m);
        assert(devlink);
        assert(ready_units);
        assert(not_ready_units);

        if (sd_device_new_from_devname(&dev, devlink) >= 0 && device_is_ready(dev)) {
                if (MANAGER_IS_RUNNING(m) && device_is_processed(dev) <= 0)
                        /* The device is being processed by udevd. We will receive relevant uevent for the
                         * device later when completed. Let's ignore the device now. */
                        return 0;

                /* Note, even if the device is being processed by udevd, setup the unit on enumerate.
                 * See also the comments in device_catchup(). */
                return device_setup_unit(m, dev, devlink, /* main = */ false, ready_units);
        }

        /* the devlink is already removed or not ready */
        if (device_by_path(m, devlink, &u) < 0)
                return 0; /* The corresponding .device unit not found. That's fine. */

        return set_ensure_put(not_ready_units, NULL, DEVICE(u));
}

static int device_setup_extra_units(Manager *m, sd_device *dev, Set **ready_units, Set **not_ready_units) {
        _cleanup_strv_free_ char **aliases = NULL;
        const char *syspath, *devname = NULL;
        Device *l;
        int r;

        assert(m);
        assert(dev);
        assert(ready_units);
        assert(not_ready_units);

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return r;

        (void) sd_device_get_devname(dev, &devname);

        /* devlink units */
        FOREACH_DEVICE_DEVLINK(dev, devlink) {
                /* These are a kind of special devlink. They should be always unique, but neither persistent
                 * nor predictable. Hence, let's refuse them. See also the comments for alias units below. */
                if (PATH_STARTSWITH_SET(devlink, "/dev/block/", "/dev/char/"))
                        continue;

                (void) device_setup_devlink_unit_one(m, devlink, ready_units, not_ready_units);
        }

        if (device_is_ready(dev)) {
                const char *s;

                r = sd_device_get_property_value(dev, "SYSTEMD_ALIAS", &s);
                if (r < 0 && r != -ENOENT)
                        log_device_warning_errno(dev, r, "Failed to get SYSTEMD_ALIAS property, ignoring: %m");
                if (r >= 0) {
                        r = strv_split_full(&aliases, s, NULL, EXTRACT_UNQUOTE);
                        if (r < 0)
                                log_device_warning_errno(dev, r, "Failed to parse SYSTEMD_ALIAS property, ignoring: %m");
                }
        }

        /* alias units */
        STRV_FOREACH(alias, aliases) {
                if (!path_is_absolute(*alias)) {
                        log_device_warning(dev, "The alias \"%s\" specified in SYSTEMD_ALIAS is not an absolute path, ignoring.", *alias);
                        continue;
                }

                if (!path_is_safe(*alias)) {
                        log_device_warning(dev, "The alias \"%s\" specified in SYSTEMD_ALIAS is not safe, ignoring.", *alias);
                        continue;
                }

                /* Note, even if the devlink is not persistent, LVM expects /dev/block/ symlink units exist.
                 * To achieve that, they set the path to SYSTEMD_ALIAS. Hence, we cannot refuse aliases start
                 * with /dev/, unfortunately. */

                (void) device_setup_unit(m, dev, *alias, /* main = */ false, ready_units);
        }

        l = hashmap_get(m->devices_by_sysfs, syspath);
        LIST_FOREACH(same_sysfs, d, l) {
                if (!d->path)
                        continue;

                if (path_equal(d->path, syspath))
                        continue; /* This is the main unit. */

                if (devname && path_equal(d->path, devname))
                        continue; /* This is the real device node. */

                if (device_has_devlink(dev, d->path))
                        continue; /* The devlink was already processed in the above loop. */

                if (strv_contains(aliases, d->path))
                        continue; /* This is already processed in the above, and ready. */

                if (path_startswith(d->path, "/dev/"))
                        /* This is a devlink unit. Check existence and update syspath. */
                        (void) device_setup_devlink_unit_one(m, d->path, ready_units, not_ready_units);
                else
                        /* This is an alias unit of dropped or not ready device. */
                        (void) set_ensure_put(not_ready_units, NULL, d);
        }

        return 0;
}

static int device_setup_units(Manager *m, sd_device *dev, Set **ret_ready_units, Set **ret_not_ready_units) {
        _cleanup_set_free_ Set *ready_units = NULL, *not_ready_units = NULL;
        const char *syspath, *devname = NULL;
        int r;

        assert(m);
        assert(dev);
        assert(ret_ready_units);
        assert(ret_not_ready_units);

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Couldn't get syspath from device, ignoring: %m");

        /* First, process the main (that is, points to the syspath) and (real, not symlink) devnode units. */
        if (device_for_action(dev, SD_DEVICE_REMOVE))
                /* If the device is removed, the main and devnode units will be removed by
                 * device_update_found_by_sysfs() in device_dispatch_io(). Hence, it is not necessary to
                 * store them to not_ready_units, and we have nothing to do here.
                 *
                 * Note, still we need to process devlink units below, as a devlink previously points to this
                 * device may still exist and now point to another device node. That is, do not forget to
                 * call device_setup_extra_units(). */
                ;
        else if (device_is_ready(dev)) {
                /* Add the main unit named after the syspath. If this one fails, don't bother with the rest,
                 * as this one shall be the main device unit the others just follow. (Compare with how
                 * device_following() is implemented, see below, which looks for the sysfs device.) */
                r = device_setup_unit(m, dev, syspath, /* main = */ true, &ready_units);
                if (r < 0)
                        return r;

                /* Add an additional unit for the device node */
                if (sd_device_get_devname(dev, &devname) >= 0)
                        (void) device_setup_unit(m, dev, devname, /* main = */ false, &ready_units);

        } else {
                Unit *u;

                /* If the device exists but not ready, then save the units and unset udev bits later. */

                if (device_by_path(m, syspath, &u) >= 0) {
                        r = set_ensure_put(&not_ready_units, NULL, DEVICE(u));
                        if (r < 0)
                                log_unit_debug_errno(u, r, "Failed to store unit, ignoring: %m");
                }

                if (sd_device_get_devname(dev, &devname) >= 0 &&
                    device_by_path(m, devname, &u) >= 0) {
                        r = set_ensure_put(&not_ready_units, NULL, DEVICE(u));
                        if (r < 0)
                                log_unit_debug_errno(u, r, "Failed to store unit, ignoring: %m");
                }
        }

        /* Next, add/update additional .device units point to aliases and symlinks. */
        (void) device_setup_extra_units(m, dev, &ready_units, &not_ready_units);

        /* Safety check: no unit should be in ready_units and not_ready_units simultaneously. */
        Unit *u;
        SET_FOREACH(u, not_ready_units)
                if (set_remove(ready_units, u))
                        log_unit_error(u, "Cannot activate and deactivate the unit simultaneously. Deactivating.");

        *ret_ready_units = TAKE_PTR(ready_units);
        *ret_not_ready_units = TAKE_PTR(not_ready_units);
        return 0;
}

static Unit *device_following(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u)), *first = NULL;

        if (startswith(u->id, "sys-"))
                return NULL;

        /* Make everybody follow the unit that's named after the sysfs path */
        LIST_FOREACH(same_sysfs, other, d->same_sysfs_next)
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

        LIST_FOREACH_BACKWARDS(same_sysfs, other, d->same_sysfs_prev) {
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

                first = other;
        }

        return UNIT(first);
}

static int device_following_set(Unit *u, Set **ret) {
        Device *d = ASSERT_PTR(DEVICE(u));
        _cleanup_set_free_ Set *set = NULL;
        int r;

        assert(ret);

        if (LIST_JUST_US(same_sysfs, d)) {
                *ret = NULL;
                return 0;
        }

        set = set_new(NULL);
        if (!set)
                return -ENOMEM;

        LIST_FOREACH(same_sysfs, other, d->same_sysfs_next) {
                r = set_put(set, other);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH_BACKWARDS(same_sysfs, other, d->same_sysfs_prev) {
                r = set_put(set, other);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(set);
        return 1;
}

static void device_shutdown(Manager *m) {
        assert(m);

        m->device_monitor = sd_device_monitor_unref(m->device_monitor);
        m->devices_by_sysfs = hashmap_free(m->devices_by_sysfs);
}

static void device_enumerate(Manager *m) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(m);

        if (!m->device_monitor) {
                r = sd_device_monitor_new(&m->device_monitor);
                if (r < 0) {
                        log_error_errno(r, "Failed to allocate device monitor: %m");
                        goto fail;
                }

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
                _cleanup_set_free_ Set *ready_units = NULL, *not_ready_units = NULL;
                const char *syspath;
                bool processed;
                Device *d;

                r = sd_device_get_syspath(dev, &syspath);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to get syspath of enumerated device, ignoring: %m");
                        continue;
                }

                r = device_is_processed(dev);
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to check if device is processed by udevd, assuming not: %m");
                processed = r > 0;

                if (device_setup_units(m, dev, &ready_units, &not_ready_units) < 0)
                        continue;

                SET_FOREACH(d, ready_units) {
                        device_update_found_one(d, DEVICE_FOUND_UDEV, DEVICE_FOUND_UDEV);

                        /* Why we need to check the syspath here? Because the device unit may be generated by
                         * a devlink, and the syspath may be different from the one of the original device. */
                        if (path_equal(d->sysfs, syspath))
                                d->processed = processed;
                }
                SET_FOREACH(d, not_ready_units)
                        device_update_found_one(d, DEVICE_NOT_FOUND, DEVICE_FOUND_UDEV);
        }

        return;

fail:
        device_shutdown(m);
}

static void device_propagate_reload(Manager *m, Device *d) {
        int r;

        assert(m);
        assert(d);

        if (d->state == DEVICE_DEAD)
                return;

        r = manager_propagate_reload(m, UNIT(d), JOB_REPLACE, NULL);
        if (r < 0)
                log_unit_warning_errno(UNIT(d), r, "Failed to propagate reload, ignoring: %m");
}

static void device_remove_old_on_move(Manager *m, sd_device *dev) {
        _cleanup_free_ char *syspath_old = NULL;
        const char *devpath_old;
        int r;

        assert(m);
        assert(dev);

        r = sd_device_get_property_value(dev, "DEVPATH_OLD", &devpath_old);
        if (r < 0)
                return (void) log_device_debug_errno(dev, r, "Failed to get DEVPATH_OLD= property on 'move' uevent, ignoring: %m");

        syspath_old = path_join("/sys", devpath_old);
        if (!syspath_old)
                return (void) log_oom();

        device_update_found_by_sysfs(m, syspath_old, DEVICE_NOT_FOUND, _DEVICE_FOUND_MASK);
}

static int device_dispatch_io(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_device_action_t action;
        const char *sysfs;
        bool ready;
        Device *d;
        int r;

        assert(dev);

        log_device_uevent(dev, "Processing udev action");

        r = sd_device_get_syspath(dev, &sysfs);
        if (r < 0) {
                log_device_warning_errno(dev, r, "Failed to get device syspath, ignoring: %m");
                return 0;
        }

        r = sd_device_get_action(dev, &action);
        if (r < 0) {
                log_device_warning_errno(dev, r, "Failed to get udev action, ignoring: %m");
                return 0;
        }

        log_device_debug(dev, "Got '%s' action on syspath '%s'.", device_action_to_string(action), sysfs);

        if (action == SD_DEVICE_MOVE)
                device_remove_old_on_move(m, dev);

        /* When udevd failed to process the device, SYSTEMD_ALIAS or any other properties may contain invalid
         * values. Let's refuse to handle the uevent. */
        if (sd_device_get_property_value(dev, "UDEV_WORKER_FAILED", NULL) >= 0) {
                int v;

                if (device_get_property_int(dev, "UDEV_WORKER_ERRNO", &v) >= 0)
                        log_device_warning_errno(dev, v, "systemd-udevd failed to process the device, ignoring: %m");
                else if (device_get_property_int(dev, "UDEV_WORKER_EXIT_STATUS", &v) >= 0)
                        log_device_warning(dev, "systemd-udevd failed to process the device with exit status %i, ignoring.", v);
                else if (device_get_property_int(dev, "UDEV_WORKER_SIGNAL", &v) >= 0) {
                        const char *s;
                        (void) sd_device_get_property_value(dev, "UDEV_WORKER_SIGNAL_NAME", &s);
                        log_device_warning(dev, "systemd-udevd failed to process the device with signal %i(%s), ignoring.", v, strna(s));
                } else
                        log_device_warning(dev, "systemd-udevd failed to process the device with unknown result, ignoring.");

                return 0;
        }

        /* A change event can signal that a device is becoming ready, in particular if the device is using
         * the SYSTEMD_READY logic in udev so we need to reach the else block of the following if, even for
         * change events */
        ready = device_is_ready(dev);

        _cleanup_set_free_ Set *ready_units = NULL, *not_ready_units = NULL;
        (void) device_setup_units(m, dev, &ready_units, &not_ready_units);

        if (action == SD_DEVICE_REMOVE) {
                r = swap_process_device_remove(m, dev);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to process swap device remove event, ignoring: %m");
        } else if (ready) {
                r = swap_process_device_new(m, dev);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to process swap device new event, ignoring: %m");
        }

        if (!IN_SET(action, SD_DEVICE_ADD, SD_DEVICE_REMOVE, SD_DEVICE_MOVE))
                SET_FOREACH(d, ready_units)
                        device_propagate_reload(m, d);

        if (!set_isempty(ready_units))
                manager_dispatch_load_queue(m);

        if (action == SD_DEVICE_REMOVE)
                /* If we get notified that a device was removed by udev, then it's completely gone, hence
                 * unset all found bits. Note this affects all .device units still point to the removed
                 * device. */
                device_update_found_by_sysfs(m, sysfs, DEVICE_NOT_FOUND, _DEVICE_FOUND_MASK);

        /* These devices are found and ready now, set the udev found bit. Note, this is also necessary to do
         * on remove uevent, as some devlinks may be updated and now point to other device nodes. */
        SET_FOREACH(d, ready_units)
                device_update_found_one(d, DEVICE_FOUND_UDEV, DEVICE_FOUND_UDEV);

        /* These devices may be nominally around, but not ready for us. Hence unset the udev bit, but leave
         * the rest around. This may be redundant for remove uevent, but should be harmless. */
        SET_FOREACH(d, not_ready_units)
                device_update_found_one(d, DEVICE_NOT_FOUND, DEVICE_FOUND_UDEV);

        return 0;
}

void device_found_node(Manager *m, const char *node, DeviceFound found, DeviceFound mask) {
        int r;

        assert(m);
        assert(node);
        assert(!FLAGS_SET(mask, DEVICE_FOUND_UDEV));

        if (!udev_available())
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
                 * everything is alright with the device node. Note that we're fine with missing device nodes,
                 * but not with badly set up ones. */

                r = sd_device_new_from_devname(&dev, node);
                if (r == -ENODEV)
                        log_debug("Could not find device for %s, continuing without device node", node);
                else if (r < 0) {
                        /* Reduce log noise from nodes which are not device nodes by skipping EINVAL. */
                        if (r != -EINVAL)
                                log_error_errno(r, "Failed to open %s device, ignoring: %m", node);
                        return;
                }

                (void) device_setup_unit(m, dev, node, /* main = */ false, NULL); /* 'dev' may be NULL. */
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

        .following = device_following,
        .following_set = device_following_set,

        .enumerate = device_enumerate,
        .shutdown = device_shutdown,
        .supported = udev_available,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Expecting device %s...",
                        [1] = "Waiting for device %s to disappear...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Found device %s.",
                        [JOB_TIMEOUT]    = "Timed out waiting for device %s.",
                },
        },
};
