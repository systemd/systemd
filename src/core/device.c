/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "dbus-unit.h"
#include "device.h"
#include "device-private.h"
#include "device-util.h"
#include "extract-word.h"
#include "hashmap.h"
#include "log.h"
#include "manager.h"
#include "path-util.h"
#include "serialize.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "swap.h"
#include "udev-util.h"
#include "unit.h"
#include "unit-name.h"

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

        return 1; /* updated */
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

        if (state == DEVICE_PLUGGED)
                d->has_plugged = true;
        if (state == DEVICE_DEAD)
                d->has_plugged = false;

        /* Didn't exist before, but does now? If so, generate a new invocation ID for it. */
        if (state != DEVICE_DEAD &&
            (!unit_has_invocation_id(UNIT(d)) ||
             (d->state == DEVICE_DEAD && MANAGER_IS_RUNNING(UNIT(d)->manager))))
                (void) unit_acquire_invocation_id(UNIT(d));

        if (d->state != state)
                bus_unit_send_pending_change_signal(UNIT(d), false);

        old_state = d->state;
        d->state = state;

        if (state == DEVICE_DEAD)
                device_unset_sysfs(d);

        if (state != old_state)
                log_unit_debug(UNIT(d), "Changed %s -> %s", device_state_to_string(old_state), device_state_to_string(state));

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state], /* reload_success= */ true);
}

static void device_found_changed(Device *d, DeviceFound previous, DeviceFound now) {
        assert(d);

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
         *    Device.enumerated_found is applied to Device.found, and state is updated based on that. */

        if (!d->sysfs) {
                /* There are several possibilities:
                 * - The device is removed after serialization. In that case, we should downgrade the
                 *   serialized state to dead. See also device_update_found_one().
                 * - We did not know the sysfs path when the unit was serialized. If a mount or swap unit
                 *   sees the device ('found' has DEVICE_FOUND_MOUNT/_SWAP), the state should be tentative,
                 *   and let's keep it. If no mount/swap unit references the device, enter the dead state.
                 * - The serialization is generated by one older than v253
                 *   (1ea74fca3a3c737f3901bc10d879b7830b3528bf). There is nothing we can do. Downgrade the
                 *   state if it is plugged. */
                found &= ~DEVICE_FOUND_UDEV;
                if (state == DEVICE_PLUGGED || found == DEVICE_NOT_FOUND) {
                        state = DEVICE_DEAD;
                        d->has_plugged = false;
                }
        }

        /* Just as we ignore the DEVICE_FOUND_UDEV_READY flag on serialization, let's downgrade the
         * DEVICE_PLUGGED state to DEVICE_TENTATIVE. */
        if (state == DEVICE_PLUGGED)
                state = DEVICE_TENTATIVE;

        if (d->found == found && d->state == state)
                return 0;

        d->found = found;
        device_set_state(d, state);
        return 0;
}

static void device_catchup(Unit *u) {
        Device *d = ASSERT_PTR(DEVICE(u));

        /* Second, let's update the state with the enumerated state.
         *
         * Note, we only enumerate ready devices in device_enumerate(). So, here we should not drop the
         * DEVICE_FOUND_UDEV_EXIST flag if we verified that the device exists. See device_coldplug() and
         * device_deserialize_sysfs(). */
        DeviceFound found = d->enumerated_found | (d->found & DEVICE_FOUND_UDEV_EXIST);
        device_update_found_one(d, found, _DEVICE_FOUND_MASK);
}

/* On serialize/deserialize, we use DEVICE_FOUND_UDEV_EXIST rather than DEVICE_FOUND_UDEV. This is important
 * especially when switching-root, as the udev rules files in initrd and the host are typically different,
 * hence a device that was ready before switching-root is not guaranteed to still be ready. */
static const struct {
        DeviceFound flag;
        const char *name;
} device_found_map[] = {
        { DEVICE_FOUND_UDEV_EXIST, "found-udev"  },
        { DEVICE_FOUND_MOUNT,      "found-mount" },
        { DEVICE_FOUND_SWAP,       "found-swap"  },
};

static int device_found_to_string_many(DeviceFound flags, char **ret) {
        _cleanup_free_ char *s = NULL;

        assert((flags & ~_DEVICE_FOUND_MASK) == 0);
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

        (void) serialize_bool_elide(f, "has-plugged", d->has_plugged);

        return 0;
}

static int device_deserialize_sysfs(Device *d, const char *value) {
        int r;

        assert(d);

        if (d->sysfs)
                return 0; /* already enumerated or deserialized. */

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_syspath(&dev, value);
        if (r < 0)
                return log_unit_debug_errno(
                                UNIT(d), r,
                                "Failed to validate deserialized sysfs path '%s': %m",
                                value);

        /* For safety, normalize the syspath. */
        const char *syspath;
        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return log_unit_debug_errno(
                                UNIT(d), r,
                                "Failed to get syspath from sd_device generated from deserialized sysfs path '%s': %m",
                                value);

        r = device_set_sysfs(d, syspath);
        if (r < 0)
                return log_unit_debug_errno(
                                UNIT(d), r,
                                "Failed to set deserialized sysfs path '%s': %m",
                                syspath);

        return 0;
}

static int device_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Device *d = ASSERT_PTR(DEVICE(u));
        int r;

        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "sysfs"))
                (void) device_deserialize_sysfs(d, value);

        else if (streq(key, "path")) {
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

        } else if (streq(key, "has-plugged")) {
                r = parse_boolean(value);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse has-plugged value '%s', ignoring: %m", value);
                else
                        d->has_plugged = r;

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
                        /* If this is not a template, then let's mangle it so that it becomes a valid unit name. */

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

static int device_setup_unit(Manager *m, sd_device *dev, const char *path, DeviceFound found) {
        int r;

        assert(m);
        assert(path);
        assert(dev || found != DEVICE_FOUND_UDEV);
        assert(IN_SET(found, DEVICE_FOUND_UDEV, DEVICE_FOUND_MOUNT, DEVICE_FOUND_SWAP));

        const char *sysfs = NULL;
        if (dev) {
                r = sd_device_get_syspath(dev, &sysfs);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Couldn't get syspath from device: %m");
        }

        _cleanup_free_ char *e = NULL;
        r = unit_name_from_path(path, ".device", &e);
        if (r < 0)
                return log_struct_errno(
                                LOG_WARNING, r,
                                LOG_MESSAGE_ID(SD_MESSAGE_DEVICE_PATH_NOT_SUITABLE_STR),
                                LOG_ITEM("DEVICE=%s", path),
                                LOG_MESSAGE("Failed to generate valid unit name from device path '%s': %m",
                                            path));

        _cleanup_(unit_freep) Unit *new_unit = NULL;
        Unit *u = manager_get_unit(m, e);
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

        /* If this was created via some dependency and has not actually been seen yet, ->sysfs will not be
         * initialized. Hence initialize it if necessary. */
        bool sysfs_updated = false;
        if (sysfs) {
                r = device_set_sysfs(d, sysfs);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to set sysfs path %s: %m", sysfs);
                sysfs_updated = r > 0;

                /* The additional systemd udev properties we only interpret for the main object */
                if (path_equal(sysfs, path))
                        (void) device_add_udev_wants(u, dev);
        }

        (void) device_update_description(u, dev, path);

        /* So the user wants the mount units to be bound to the device but a mount unit might have been seen
         * by systemd before the device appears on its radar. In this case the device unit is partially
         * initialized and includes the deps on the mount unit but at that time the "bind mounts" flag wasn't
         * present. Fix this up now. */
        if (dev && device_is_bound_by_mounts(d, dev))
                device_upgrade_mount_deps(u);

        /* Before updating the device state and/or propagating reload, we need to dispatch load queue. */
        manager_dispatch_load_queue(m);

        /* Propagate reload if the device unit has been already active and is still active. */
        bool has_plugged = d->has_plugged;
        device_update_found_one(d, found, found);

        /* Propagate reload if the device was plugged and also currently plugged, and a property of the
         * device unit may be changed (sysfs is changed or get an event for the device). */
        if (MANAGER_IS_RUNNING(m) && found == DEVICE_FOUND_UDEV &&
            has_plugged && d->state == DEVICE_PLUGGED &&
            (sysfs_updated || sd_device_get_action(dev, /* ret= */ NULL) >= 0)) {
                r = manager_propagate_reload(m, u, JOB_REPLACE, /* e= */ NULL);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to propagate reload, ignoring: %m");
        }

        TAKE_PTR(new_unit);
        return 0;
}

typedef enum DeviceBusyFlag {
        DEVICE_BUSY_NONE       = 0,
        DEVICE_BUSY_REMOVING   = 1 << 0, /* on 'remove' event */
        DEVICE_BUSY_RENAMING   = 1 << 1, /* has ID_RENAMING=1 */
        DEVICE_BUSY_NO_TAG     = 1 << 2, /* currently does not have 'systemd' tag */
        DEVICE_BUSY_NOT_READY  = 1 << 3, /* has SYSTEMD_READY=0 */
        DEVICE_BUSY_PROCESSING = 1 << 4, /* has ID_PROCESSING=1, or does not have udev database */
} DeviceBusyFlag;

static DeviceBusyFlag device_get_busy_flags(sd_device *dev) {
        DeviceBusyFlag flags = DEVICE_BUSY_NONE;
        int r;

        assert(dev);

        if (device_for_action(dev, SD_DEVICE_REMOVE))
                return DEVICE_BUSY_REMOVING;

        r = device_is_renaming(dev);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to check if device is renaming, assuming device is not renaming: %m");
        if (r > 0) {
                log_device_debug(dev, "Device busy: device is renaming.");
                flags |= DEVICE_BUSY_RENAMING;
        }

        /* Is it really tagged as 'systemd' right now? */
        r = sd_device_has_current_tag(dev, "systemd");
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to check if device has \"systemd\" tag, assuming device is not tagged with \"systemd\": %m");
        if (r == 0)
                log_device_debug(dev, "Device busy: device is not tagged with \"systemd\".");
        if (r <= 0)
                flags |= DEVICE_BUSY_NO_TAG;

        r = device_get_property_bool(dev, "SYSTEMD_READY"); /* Defaults to ready. */
        if (r < 0 && r != -ENOENT)
                log_device_warning_errno(dev, r, "Failed to get device SYSTEMD_READY property, assuming device does not have \"SYSTEMD_READY\" property: %m");
        if (r == 0) {
                log_device_debug(dev, "Device busy: SYSTEMD_READY property from device is false.");
                flags |= DEVICE_BUSY_NOT_READY;
        }

        r = device_is_processed(dev);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to check if device has been processed by udevd, assuming not: %m");
        if (r <= 0) {
                log_device_debug(dev, "Device busy: device has ID_PROCESSING=1 property or does not have udev database file.");
                flags |= DEVICE_BUSY_PROCESSING;
        }

        return flags;
}

static int device_has_same_syspath(sd_device *a, sd_device *b) {
        const char *patha, *pathb;
        int r;

        assert(a);
        assert(b);

        r = sd_device_get_syspath(a, &patha);
        if (r < 0)
                return r;

        r = sd_device_get_syspath(b, &pathb);
        if (r < 0)
                return r;

        return path_equal(patha, pathb);
}

static int device_setup_devlink_unit_one(Manager *m, sd_device *dev, DeviceBusyFlag busy_flags, const char *devlink) {
        int r;

        assert(m);
        assert(dev);
        assert(devlink);

        _cleanup_(sd_device_unrefp) sd_device *dev_by_devlink = NULL;
        r = sd_device_new_from_devname(&dev_by_devlink, devlink);
        if (r < 0) {
                if (!ERRNO_IS_NEG_DEVICE_ABSENT(r))
                        log_device_warning_errno(
                                        dev, r,
                                        "Failed to acquire sd_device for '%s', assuming the device node symlink is gone: %m",
                                        devlink);

                /* The devlink is gone. Drop both DEVICE_FOUND_UDEV_EXIST and _READY flags. */
                device_update_found_by_name(m, devlink, DEVICE_NOT_FOUND, DEVICE_FOUND_UDEV);
                return 0;
        }

        /* If the devlink points to our device node, use the original sd_device object, so that we can avoid
         * parsing uevent and udev database again. */
        r = device_has_same_syspath(dev, dev_by_devlink);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to compare device syspath: %m");
        if (r > 0) {
                /* The devlink points to the device we are currently processing. */

                if (busy_flags != DEVICE_BUSY_NONE) {
                        /* The devlink itself exists, but the device is not ready. Drop the _READY flag. */
                        device_update_found_by_name(m, devlink, DEVICE_NOT_FOUND, DEVICE_FOUND_UDEV_READY);
                        return 0;
                }
        } else {
                /* The devlink points to a device other than the one we are currently processing. */
                dev = dev_by_devlink;

                if (device_get_busy_flags(dev) != DEVICE_BUSY_NONE)
                        /* The devlink may be tentatively not-ready (e.g. by ID_PROCESSING=1). Let's keep the
                         * state of the unit now. If this will be really gone, we will hopefully receive a
                         * uevent about that later. */
                        return 0;
        }

        /* The devlink is ready. Setup/update the device unit. */
        return device_setup_unit(m, dev, devlink, DEVICE_FOUND_UDEV);
}

static int device_setup_units(Manager *m, sd_device *dev, DeviceBusyFlag busy_flags) {
        int r;

        assert(m);
        assert(dev);

        const char *syspath;
        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Couldn't get syspath from device: %m");

        const char *devname = NULL;
        (void) sd_device_get_devname(dev, &devname);

        /* The mask is used for not-ready units. If the main device is ready or on a remove event, we know
         * that the information is authoritative, hence we can drop both DEVICE_FOUND_UDEV_EXIST and _READY
         * flags. On other uevents, the device may be tentatively not-ready, hence we only drop the
         * DEVICE_FOUND_UDEV_READY flag. */
        DeviceFound mask =
                IN_SET(busy_flags, DEVICE_BUSY_NONE, DEVICE_BUSY_REMOVING) ?
                DEVICE_FOUND_UDEV : DEVICE_FOUND_UDEV_READY;

        /* First, process the main (that is, points to the syspath) and (real, not symlink) devnode units. */
        if (busy_flags == DEVICE_BUSY_NONE) {
                /* Add the main unit named after the syspath. If this one fails, don't bother with the rest,
                 * as this one shall be the main device unit the others just follow. (Compare with how
                 * device_following() is implemented, see below, which looks for the sysfs device.) */
                r = device_setup_unit(m, dev, syspath, DEVICE_FOUND_UDEV);
                if (r < 0)
                        return r;

                /* Add an additional unit for the device node. */
                if (devname)
                        (void) device_setup_unit(m, dev, devname, DEVICE_FOUND_UDEV);

        } else {
                device_update_found_by_name(m, syspath, DEVICE_NOT_FOUND, mask);
                if (devname)
                        device_update_found_by_name(m, devname, DEVICE_NOT_FOUND, mask);
        }

        /* Setup/update devlink units. Note, this must be done also if the device is not ready. */
        FOREACH_DEVICE_DEVLINK(dev, devlink) {
                /* These are a kind of special devlink. They should be always unique, but neither persistent
                 * nor predictable. Hence, let's refuse them. See also the comments for alias units below. */
                if (PATH_STARTSWITH_SET(devlink, "/dev/block/", "/dev/char/"))
                        continue;

                (void) device_setup_devlink_unit_one(m, dev, busy_flags, devlink);
        }

        /* Setup alias units. */
        _cleanup_strv_free_ char **aliases = NULL;
        if (busy_flags == DEVICE_BUSY_NONE) {
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

        STRV_FOREACH(alias, aliases) {
                if (!path_is_absolute(*alias)) {
                        log_device_warning(dev, "The alias \"%s\" specified in SYSTEMD_ALIAS is not an absolute path, ignoring.", *alias);
                        continue;
                }

                if (!path_is_safe(*alias)) {
                        log_device_warning(dev, "The alias \"%s\" specified in SYSTEMD_ALIAS is not safe, ignoring.", *alias);
                        continue;
                }

                /* Note, even if the devlink is not persistent, LVM expects /dev/block/ symlink units to
                 * exist. To achieve that, they set the path to SYSTEMD_ALIAS. Hence, we cannot refuse
                 * aliases that start with /dev/, unfortunately. */

                (void) device_setup_unit(m, dev, *alias, DEVICE_FOUND_UDEV);
        }

        /* Update the existing units that point to the same sysfs. */
        Device *l = hashmap_get(m->devices_by_sysfs, syspath);
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
                        (void) device_setup_devlink_unit_one(m, dev, busy_flags, d->path);
                else
                        /* This is an alias unit of dropped or not ready device. */
                        device_update_found_one(d, DEVICE_NOT_FOUND, mask);
        }

        return 0;
}

static Unit* device_following(Unit *u) {
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

        FOREACH_DEVICE(e, dev)
                if (device_get_busy_flags(dev) == DEVICE_BUSY_NONE)
                        (void) device_setup_units(m, dev, DEVICE_BUSY_NONE);

        return;

fail:
        device_shutdown(m);
}

static int device_remove_old_on_move(Manager *m, sd_device *dev) {
        int r;

        assert(m);
        assert(dev);

        if (!device_for_action(dev, SD_DEVICE_MOVE))
                return 0;

        const char *devpath_old;
        r = sd_device_get_property_value(dev, "DEVPATH_OLD", &devpath_old);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get DEVPATH_OLD= property on 'move' uevent: %m");

        _cleanup_free_ char *syspath_old = path_join("/sys", devpath_old);
        if (!syspath_old)
                return log_oom_debug();

        device_update_found_by_sysfs(m, syspath_old, DEVICE_NOT_FOUND, DEVICE_FOUND_UDEV);
        return 0;
}

static int device_dispatch_io(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_device_action_t action;
        const char *sysfs;
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

        DeviceBusyFlag busy_flags = device_get_busy_flags(dev);
        (void) device_setup_units(m, dev, busy_flags);

        /* Drop all devices that points to the old syspath. */
        (void) device_remove_old_on_move(m, dev);

        if (FLAGS_SET(busy_flags, DEVICE_BUSY_REMOVING)) {
                r = swap_process_device_remove(m, dev);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to process swap device remove event, ignoring: %m");
        } else if (busy_flags == DEVICE_BUSY_NONE) {
                r = swap_process_device_new(m, dev);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to process swap device new event, ignoring: %m");
        }

        log_device_uevent(dev, "Processed udev action");
        return 0;
}

void device_found_node(Manager *m, const char *node, DeviceFound found, DeviceFound mask) {
        int r;

        assert(m);
        assert(node);
        assert(IN_SET(mask, DEVICE_FOUND_MOUNT, DEVICE_FOUND_SWAP));
        assert(found == mask || found == DEVICE_NOT_FOUND);

        /* This is called whenever we find a device referenced in /proc/swaps or /proc/self/mounts. Such a
         * device might be mounted/enabled at a time where udev has not finished probing it yet, and we thus
         * haven't learned about it yet. In this case we will set the device unit to "tentative" state. */

        if (!udev_available())
                return;

        if (found == DEVICE_NOT_FOUND) {
                device_update_found_by_name(m, node, found, mask);
                return;
        }

        /* If the device is known in the kernel and newly appeared, then we'll create a device unit for it,
         * under the name referenced in /proc/swaps or /proc/self/mountinfo. But first, let's validate if
         * everything is alright with the device node. Note that we're fine with missing device nodes, but
         * not with badly set up ones. */

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_devname(&dev, node);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                log_debug("Could not find device for '%s', continuing without device node.", node);
        else if (r == -EINVAL)
                return; /* Not a device node. */
        else if (r < 0)
                return (void) log_warning_errno(r, "Failed to open device node '%s', ignoring: %m", node);

        (void) device_setup_unit(m, dev, node, found); /* 'dev' may be NULL. */
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
