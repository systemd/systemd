/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "device-internal.h"
#include "device-util.h"
#include "format-util.h"
#include "io-util.h"
#include "mountpoint-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "strv.h"

static void device_unref_many(sd_device **devices, size_t n) {
        assert(devices || n == 0);

        for (size_t i = 0; i < n; i++)
                sd_device_unref(devices[i]);
}

static int monitor_set_nl_address(sd_device_monitor *m) {
        union sockaddr_union snl;
        socklen_t addrlen;

        assert(m);

        /* Get the address the kernel has assigned us.
         * It is usually, but not necessarily the pid. */
        addrlen = sizeof(struct sockaddr_nl);
        if (getsockname(m->sock, &snl.sa, &addrlen) < 0)
                return -errno;

        m->snl.nl.nl_pid = snl.nl.nl_pid;
        return 0;
}

void device_enumerator_unref_devices(sd_device_enumerator *enumerator) {
        assert(enumerator);

        hashmap_clear_with_destructor(enumerator->devices_by_syspath, sd_device_unref);
        device_unref_many(enumerator->devices, enumerator->n_devices);
        enumerator->devices = mfree(enumerator->devices);
        enumerator->n_devices = 0;
}

int device_enumerator_add_prioritized_subsystem(sd_device_enumerator *enumerator, const char *subsystem) {
        int r;

        assert(enumerator);
        assert(subsystem);

        if (strv_contains(enumerator->prioritized_subsystems, subsystem))
                return 0;

        r = strv_extend(&enumerator->prioritized_subsystems, subsystem);
        if (r < 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

int device_enumerator_add_match_parent_incremental(sd_device_enumerator *enumerator, sd_device *parent) {
        const char *path;
        int r;

        assert(enumerator);
        assert(parent);

        r = sd_device_get_syspath(parent, &path);
        if (r < 0)
                return r;

        r = set_put_strdup(&enumerator->match_parent, path);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

sd_device* device_enumerator_get_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate)
                return NULL;

        if (device_enumerator_sort_devices(enumerator) < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

sd_device* device_enumerator_get_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            !enumerator->sorted ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}

sd_device** device_enumerator_get_devices(sd_device_enumerator *enumerator, size_t *ret_n_devices) {
        assert(enumerator);
        assert(ret_n_devices);

        if (!enumerator->scan_uptodate)
                return NULL;

        if (device_enumerator_sort_devices(enumerator) < 0)
                return NULL;

        *ret_n_devices = enumerator->n_devices;
        return enumerator->devices;
}

static bool match_property(sd_device_enumerator *enumerator, sd_device *device) {
        const char *property;
        const char *value;

        assert(enumerator);
        assert(device);

        if (hashmap_isempty(enumerator->match_property))
                return true;

        HASHMAP_FOREACH_KEY(value, property, enumerator->match_property) {
                const char *property_dev, *value_dev;

                FOREACH_DEVICE_PROPERTY(device, property_dev, value_dev) {
                        if (fnmatch(property, property_dev, 0) != 0)
                                continue;

                        if (!value && !value_dev)
                                return true;

                        if (!value || !value_dev)
                                continue;

                        if (fnmatch(value, value_dev, 0) == 0)
                                return true;
                }
        }

        return false;
}

static bool match_tag(sd_device_enumerator *enumerator, sd_device *device) {
        const char *tag;

        assert(enumerator);
        assert(device);

        SET_FOREACH(tag, enumerator->match_tag)
                if (!sd_device_has_tag(device, tag))
                        return false;

        return true;
}

static bool match_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        assert(enumerator);
        assert(sysname);

        return set_fnmatch(enumerator->match_sysname, enumerator->nomatch_sysname, sysname);
}

static int match_initialized(sd_device_enumerator *enumerator, sd_device *device) {
        int r;

        assert(enumerator);
        assert(device);

        if (enumerator->match_initialized == MATCH_INITIALIZED_ALL)
                return true;

        r = sd_device_get_is_initialized(device);
        if (r == -ENOENT) /* this is necessarily racey, so ignore missing devices */
                return false;
        if (r < 0)
                return r;

        if (enumerator->match_initialized == MATCH_INITIALIZED_COMPAT) {
                /* only devices that have no devnode/ifindex or have a db entry are accepted. */
                if (r > 0)
                        return true;

                if (sd_device_get_devnum(device, NULL) >= 0)
                        return false;

                if (sd_device_get_ifindex(device, NULL) >= 0)
                        return false;

                return true;
        }

        return (enumerator->match_initialized == MATCH_INITIALIZED_NO) == (r == 0);
}

static int test_matches(
                sd_device_enumerator *enumerator,
                sd_device *device,
                bool ignore_parent_match) {

        int r;

        assert(enumerator);
        assert(device);

        /* Checks all matches, except for the sysname match (which the caller should check beforehand) */

        r = match_initialized(enumerator, device);
        if (r <= 0)
                return r;

        if (!ignore_parent_match &&
            !device_match_parent(device, enumerator->match_parent, NULL))
                return false;

        if (!match_tag(enumerator, device))
                return false;

        if (!match_property(enumerator, device))
                return false;

        if (!device_match_sysattr(device, enumerator->match_sysattr, enumerator->nomatch_sysattr))
                return false;

        return true;
}

static bool match_subsystem(sd_device_enumerator *enumerator, const char *subsystem) {
        assert(enumerator);

        if (!subsystem)
                return false;

        return set_fnmatch(enumerator->match_subsystem, enumerator->nomatch_subsystem, subsystem);
}

static int enumerator_scan_devices_tag(sd_device_enumerator *enumerator, const char *tag) {
        _cleanup_closedir_ DIR *dir = NULL;
        char *path;
        int r = 0;

        assert(enumerator);
        assert(tag);

        path = strjoina("/run/udev/tags/", tag);

        dir = opendir(path);
        if (!dir) {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "sd-device-enumerator: Failed to open tags directory %s: %m", path);
                return 0;
        }

        /* TODO: filter away subsystems? */

        FOREACH_DIRENT_ALL(de, dir, return -errno) {
                _cleanup_(sd_device_unrefp) sd_device *device = NULL;
                const char *subsystem, *sysname;
                int k;

                if (de->d_name[0] == '.')
                        continue;

                k = sd_device_new_from_device_id(&device, de->d_name);
                if (k < 0) {
                        if (k != -ENODEV)
                                /* this is necessarily racy, so ignore missing devices */
                                r = k;

                        continue;
                }

                k = sd_device_get_subsystem(device, &subsystem);
                if (k < 0) {
                        if (k != -ENOENT)
                                /* this is necessarily racy, so ignore missing devices */
                                r = k;
                        continue;
                }

                if (!match_subsystem(enumerator, subsystem))
                        continue;

                k = sd_device_get_sysname(device, &sysname);
                if (k < 0) {
                        r = k;
                        continue;
                }

                if (!match_sysname(enumerator, sysname))
                        continue;

                if (!device_match_parent(device, enumerator->match_parent, NULL))
                        continue;

                if (!match_property(enumerator, device))
                        continue;

                if (!device_match_sysattr(device, enumerator->match_sysattr, enumerator->nomatch_sysattr))
                        continue;

                k = device_enumerator_add_device(enumerator, device);
                if (k < 0) {
                        r = k;
                        continue;
                }
        }

        return r;
}

int device_enumerator_add_match_is_initialized(sd_device_enumerator *enumerator, MatchInitializedType type) {
        assert_return(enumerator, -EINVAL);
        assert_return(type >= 0 && type < _MATCH_INITIALIZED_MAX, -EINVAL);

        enumerator->match_initialized = type;

        enumerator->scan_uptodate = false;

        return 1;
}

static int sound_device_compare(const char *devpath_a, const char *devpath_b) {
        const char *sound_a, *sound_b;
        size_t prefix_len;

        assert(devpath_a);
        assert(devpath_b);

        /* For sound cards the control device must be enumerated last to make sure it's the final
         * device node that gets ACLs applied. Applications rely on this fact and use ACL changes on
         * the control node as an indicator that the ACL change of the entire sound card completed. The
         * kernel makes this guarantee when creating those devices, and hence we should too when
         * enumerating them. */

        sound_a = strstr(devpath_a, "/sound/card");
        if (!sound_a)
                return 0;

        sound_a += STRLEN("/sound/card");
        sound_a = strchr(devpath_a, '/');
        if (!sound_a)
                return 0;

        prefix_len = sound_a - devpath_a;

        if (!strneq(devpath_a, devpath_b, prefix_len))
                return 0;

        sound_b = devpath_b + prefix_len;

        return CMP(!!startswith(sound_a, "/controlC"),
                   !!startswith(sound_b, "/controlC"));
}

static bool devpath_is_late_block(const char *devpath) {
        assert(devpath);

        return strstr(devpath, "/block/md") || strstr(devpath, "/block/dm-");
}

static int device_compare(sd_device * const *a, sd_device * const *b) {
        const char *devpath_a, *devpath_b;
        int r;

        assert(a);
        assert(b);
        assert(*a);
        assert(*b);

        assert_se(sd_device_get_devpath(*(sd_device**) a, &devpath_a) >= 0);
        assert_se(sd_device_get_devpath(*(sd_device**) b, &devpath_b) >= 0);

        r = sound_device_compare(devpath_a, devpath_b);
        if (r != 0)
                return r;

        /* md and dm devices are enumerated after all other devices */
        r = CMP(devpath_is_late_block(devpath_a), devpath_is_late_block(devpath_b));
        if (r != 0)
                return r;

        return path_compare(devpath_a, devpath_b);
}

int device_enumerator_sort_devices(sd_device_enumerator *enumerator) {
        size_t n_sorted = 0, n = 0;
        sd_device **devices;
        sd_device *device;
        int r;

        assert(enumerator);

        if (enumerator->sorted)
                return 0;

        devices = new(sd_device*, hashmap_size(enumerator->devices_by_syspath));
        if (!devices)
                return -ENOMEM;

        STRV_FOREACH(prioritized_subsystem, enumerator->prioritized_subsystems) {

                for (;;) {
                        const char *syspath;
                        size_t m = n;

                        HASHMAP_FOREACH_KEY(device, syspath, enumerator->devices_by_syspath) {
                                _cleanup_free_ char *p = NULL;
                                const char *subsys;

                                if (sd_device_get_subsystem(device, &subsys) < 0)
                                        continue;

                                if (!streq(subsys, *prioritized_subsystem))
                                        continue;

                                devices[n++] = sd_device_ref(device);

                                for (;;) {
                                        _cleanup_free_ char *q = NULL;

                                        r = path_extract_directory(p ?: syspath, &q);
                                        if (r == -EADDRNOTAVAIL)
                                                break;
                                        if (r < 0)
                                                goto failed;

                                        device = hashmap_get(enumerator->devices_by_syspath, q);
                                        if (device)
                                                devices[n++] = sd_device_ref(device);

                                        free_and_replace(p, q);
                                }

                                break;
                        }

                        /* We cannot remove multiple entries in the loop HASHMAP_FOREACH_KEY() above. */
                        for (size_t i = m; i < n; i++) {
                                r = sd_device_get_syspath(devices[i], &syspath);
                                if (r < 0)
                                        goto failed;

                                assert_se(hashmap_remove(enumerator->devices_by_syspath, syspath) == devices[i]);
                                sd_device_unref(devices[i]);
                        }

                        if (m == n)
                                break;
                }

                typesafe_qsort(devices + n_sorted, n - n_sorted, device_compare);
                n_sorted = n;
        }

        HASHMAP_FOREACH(device, enumerator->devices_by_syspath)
                devices[n++] = sd_device_ref(device);

        /* Move all devices back to the hashmap. Otherwise, devices added by
         * udev_enumerate_add_syspath() -> device_enumerator_add_device() may not be listed. */
        for (size_t i = 0; i < n_sorted; i++) {
                const char *syspath;

                r = sd_device_get_syspath(devices[i], &syspath);
                if (r < 0)
                        goto failed;

                r = hashmap_put(enumerator->devices_by_syspath, syspath, devices[i]);
                if (r < 0)
                        goto failed;
                assert(r > 0);

                sd_device_ref(devices[i]);
        }

        typesafe_qsort(devices + n_sorted, n - n_sorted, device_compare);

        device_unref_many(enumerator->devices, enumerator->n_devices);

        enumerator->n_devices = n;
        free_and_replace(enumerator->devices, devices);

        enumerator->sorted = true;
        return 0;

failed:
        device_unref_many(devices, n);
        free(devices);
        return r;
}

int device_enumerator_add_device(sd_device_enumerator *enumerator, sd_device *device) {
        const char *syspath;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(device, -EINVAL);

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&enumerator->devices_by_syspath, &string_hash_ops, syspath, device);
        if (IN_SET(r, -EEXIST, 0))
                return 0;
        if (r < 0)
                return r;

        sd_device_ref(device);

        enumerator->sorted = false;
        return 1;
}

static int enumerator_add_parent_devices(
                sd_device_enumerator *enumerator,
                sd_device *device,
                bool ignore_parent_match) {

        int k, r = 0;

        assert(enumerator);
        assert(device);

        for (;;) {
                const char *ss, *usn;

                k = sd_device_get_parent(device, &device);
                if (k == -ENOENT) /* Reached the top? */
                        break;
                if (k < 0) {
                        r = k;
                        break;
                }

                k = sd_device_get_subsystem(device, &ss);
                if (k == -ENOENT) /* Has no subsystem? */
                        continue;
                if (k < 0) {
                        r = k;
                        break;
                }

                if (!match_subsystem(enumerator, ss))
                        continue;

                k = sd_device_get_sysname(device, &usn);
                if (k < 0) {
                        r = k;
                        break;
                }

                if (!match_sysname(enumerator, usn))
                        continue;

                k = test_matches(enumerator, device, ignore_parent_match);
                if (k < 0) {
                        r = k;
                        break;
                }
                if (k == 0)
                        continue;

                k = device_enumerator_add_device(enumerator, device);
                if (k < 0) {
                        r = k;
                        break;
                }
                if (k == 0) /* Exists already? Then no need to go further up. */
                        break;
        }

        return r;
}

int device_enumerator_add_parent_devices(sd_device_enumerator *enumerator, sd_device *device) {
        return enumerator_add_parent_devices(enumerator, device, /* ignore_parent_match = */ true);
}

static bool relevant_sysfs_subdir(const struct dirent *de) {
        assert(de);

        if (de->d_name[0] == '.')
                return false;

        /* Also filter out regular files and such, i.e. stuff that definitely isn't a kobject path. (Note
         * that we rely on the fact that sysfs fills in d_type here, i.e. doesn't do DT_UNKNOWN) */
        return IN_SET(de->d_type, DT_DIR, DT_LNK);
}

static int scan_dir_and_add_devices(
                sd_device_enumerator *enumerator,
                const char *basedir,
                const char *subdir1,
                const char *subdir2) {

        _cleanup_closedir_ DIR *dir = NULL;
        char *path;
        int k, r = 0;

        assert(enumerator);
        assert(basedir);

        path = strjoina("/sys/", basedir, "/");

        if (subdir1)
                path = strjoina(path, subdir1, "/");

        if (subdir2)
                path = strjoina(path, subdir2, "/");

        dir = opendir(path);
        if (!dir)
                /* this is necessarily racey, so ignore missing directories */
                return (errno == ENOENT && (subdir1 || subdir2)) ? 0 : -errno;

        FOREACH_DIRENT_ALL(de, dir, return -errno) {
                _cleanup_(sd_device_unrefp) sd_device *device = NULL;
                char syspath[strlen(path) + 1 + strlen(de->d_name) + 1];

                if (!relevant_sysfs_subdir(de))
                        continue;

                if (!match_sysname(enumerator, de->d_name))
                        continue;

                (void) sprintf(syspath, "%s%s", path, de->d_name);

                k = sd_device_new_from_syspath(&device, syspath);
                if (k < 0) {
                        if (k != -ENODEV)
                                /* this is necessarily racey, so ignore missing devices */
                                r = k;

                        continue;
                }

                k = test_matches(enumerator, device, /* ignore_parent_match = */ false);
                if (k <= 0) {
                        if (k < 0)
                                r = k;
                        continue;
                }

                k = device_enumerator_add_device(enumerator, device);
                if (k < 0)
                        r = k;

                /* Also include all potentially matching parent devices in the enumeration. These are things
                 * like root busses — e.g. /sys/devices/pci0000:00/ or /sys/devices/pnp0/, which ar not
                 * linked from /sys/class/ or /sys/bus/, hence pick them up explicitly here. */
                k = enumerator_add_parent_devices(enumerator, device, /* ignore_parent_match = */ false);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int enumerator_scan_dir(
                sd_device_enumerator *enumerator,
                const char *basedir,
                const char *subdir,
                const char *subsystem) {

        _cleanup_closedir_ DIR *dir = NULL;
        char *path;
        int r = 0;

        path = strjoina("/sys/", basedir);

        dir = opendir(path);
        if (!dir)
                return -errno;

        log_debug("sd-device-enumerator: Scanning %s", path);

        FOREACH_DIRENT_ALL(de, dir, return -errno) {
                int k;

                if (!relevant_sysfs_subdir(de))
                        continue;

                if (!match_subsystem(enumerator, subsystem ? : de->d_name))
                        continue;

                k = scan_dir_and_add_devices(enumerator, basedir, de->d_name, subdir);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int parent_add_child(sd_device_enumerator *enumerator, const char *path) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *subsystem, *sysname;
        int r;

        r = sd_device_new_from_syspath(&device, path);
        if (r == -ENODEV)
                /* this is necessarily racy, so ignore missing devices */
                return 0;
        else if (r < 0)
                return r;

        r = sd_device_get_subsystem(device, &subsystem);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        if (!match_subsystem(enumerator, subsystem))
                return 0;

        r = sd_device_get_sysname(device, &sysname);
        if (r < 0)
                return r;

        if (!match_sysname(enumerator, sysname))
                return 0;

        if (!match_property(enumerator, device))
                return 0;

        if (!device_match_sysattr(device, enumerator->match_sysattr, enumerator->nomatch_sysattr))
                return 0;

        r = device_enumerator_add_device(enumerator, device);
        if (r < 0)
                return r;

        return 1;
}

static int parent_crawl_children(sd_device_enumerator *enumerator, const char *path, unsigned maxdepth) {
        _cleanup_closedir_ DIR *dir = NULL;
        int r = 0;

        dir = opendir(path);
        if (!dir)
                return log_debug_errno(errno, "sd-device-enumerator: Failed to open parent directory %s: %m", path);

        FOREACH_DIRENT_ALL(de, dir, return -errno) {
                _cleanup_free_ char *child = NULL;
                int k;

                if (de->d_name[0] == '.')
                        continue;

                if (de->d_type != DT_DIR)
                        continue;

                child = path_join(path, de->d_name);
                if (!child)
                        return -ENOMEM;

                k = parent_add_child(enumerator, child);
                if (k < 0)
                        r = k;

                if (maxdepth > 0)
                        parent_crawl_children(enumerator, child, maxdepth - 1);
                else
                        log_debug("sd-device-enumerator: Max depth reached, %s: ignoring devices", child);
        }

        return r;
}

static int enumerator_scan_devices_children(sd_device_enumerator *enumerator) {
        const char *path;
        int r = 0, k;

        SET_FOREACH(path, enumerator->match_parent) {
                k = parent_add_child(enumerator, path);
                if (k < 0)
                        r = k;

                k = parent_crawl_children(enumerator, path, DEVICE_ENUMERATE_MAX_DEPTH);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int enumerator_scan_devices_all(sd_device_enumerator *enumerator) {
        int k, r = 0;

        log_debug("sd-device-enumerator: Scan all dirs");

        k = enumerator_scan_dir(enumerator, "bus", "devices", NULL);
        if (k < 0)
                r = log_debug_errno(k, "sd-device-enumerator: Failed to scan /sys/bus: %m");

        k = enumerator_scan_dir(enumerator, "class", NULL, NULL);
        if (k < 0)
                r = log_debug_errno(k, "sd-device-enumerator: Failed to scan /sys/class: %m");

        return r;
}

int device_enumerator_scan_devices(sd_device_enumerator *enumerator) {
        int r = 0, k;

        assert(enumerator);

        if (enumerator->scan_uptodate &&
            enumerator->type == DEVICE_ENUMERATION_TYPE_DEVICES)
                return 0;

        device_enumerator_unref_devices(enumerator);

        if (!set_isempty(enumerator->match_tag)) {
                k = enumerator_scan_devices_tags(enumerator);
                if (k < 0)
                        r = k;
        } else if (enumerator->match_parent) {
                k = enumerator_scan_devices_children(enumerator);
                if (k < 0)
                        r = k;
        } else {
                k = enumerator_scan_devices_all(enumerator);
                if (k < 0)
                        r = k;
        }

        enumerator->scan_uptodate = true;
        enumerator->type = DEVICE_ENUMERATION_TYPE_DEVICES;

        return r;
}

int enumerator_scan_devices_tags(sd_device_enumerator *enumerator) {
        const char *tag;
        int r = 0;

        assert(enumerator);

        SET_FOREACH(tag, enumerator->match_tag) {
                int k;

                k = enumerator_scan_devices_tag(enumerator, tag);
                if (k < 0)
                        r = k;
        }

        return r;
}

int device_enumerator_scan_subsystems(sd_device_enumerator *enumerator) {
        int r = 0, k;

        assert(enumerator);

        if (enumerator->scan_uptodate &&
            enumerator->type == DEVICE_ENUMERATION_TYPE_SUBSYSTEMS)
                return 0;

        device_enumerator_unref_devices(enumerator);

        /* modules */
        if (match_subsystem(enumerator, "module")) {
                k = scan_dir_and_add_devices(enumerator, "module", NULL, NULL);
                if (k < 0)
                        r = log_debug_errno(k, "sd-device-enumerator: Failed to scan modules: %m");
        }

        /* subsystems (only buses support coldplug) */
        if (match_subsystem(enumerator, "subsystem")) {
                k = scan_dir_and_add_devices(enumerator, "bus", NULL, NULL);
                if (k < 0)
                        r = log_debug_errno(k, "sd-device-enumerator: Failed to scan subsystems: %m");
        }

        /* subsystem drivers */
        if (match_subsystem(enumerator, "drivers")) {
                k = enumerator_scan_dir(enumerator, "bus", "drivers", "drivers");
                if (k < 0)
                        r = log_debug_errno(k, "sd-device-enumerator: Failed to scan drivers: %m");
        }

        enumerator->scan_uptodate = true;
        enumerator->type = DEVICE_ENUMERATION_TYPE_SUBSYSTEMS;

        return r;
}

int device_enumerator_scan_devices_and_subsystems(sd_device_enumerator *enumerator) {
        int r;

        assert(enumerator);

        if (enumerator->scan_uptodate &&
            enumerator->type == DEVICE_ENUMERATION_TYPE_ALL)
                return 0;

        device_enumerator_unref_devices(enumerator);

        if (!set_isempty(enumerator->match_tag))
                r = enumerator_scan_devices_tags(enumerator);
        else if (enumerator->match_parent)
                r = enumerator_scan_devices_children(enumerator);
        else {
                int k;

                r = enumerator_scan_devices_all(enumerator);

                if (match_subsystem(enumerator, "module")) {
                        k = scan_dir_and_add_devices(enumerator, "module", NULL, NULL);
                        if (k < 0)
                                r = log_debug_errno(k, "sd-device-enumerator: Failed to scan modules: %m");
                }
                if (match_subsystem(enumerator, "subsystem")) {
                        k = scan_dir_and_add_devices(enumerator, "bus", NULL, NULL);
                        if (k < 0)
                                r = log_debug_errno(k, "sd-device-enumerator: Failed to scan subsystems: %m");
                }

                if (match_subsystem(enumerator, "drivers")) {
                        k = enumerator_scan_dir(enumerator, "bus", "drivers", "drivers");
                        if (k < 0)
                                r = log_debug_errno(k, "sd-device-enumerator: Failed to scan drivers: %m");
                }
        }

        enumerator->scan_uptodate = true;
        enumerator->type = DEVICE_ENUMERATION_TYPE_ALL;

        return r;
}

static int check_subsystem_filter(sd_device_monitor *m, sd_device *device) {
        const char *s, *subsystem, *d, *devtype = NULL;
        int r;

        assert(m);
        assert(device);

        if (hashmap_isempty(m->subsystem_filter))
                return true;

        r = sd_device_get_subsystem(device, &subsystem);
        if (r < 0)
                return r;

        r = sd_device_get_devtype(device, &devtype);
        if (r < 0 && r != -ENOENT)
                return r;

        HASHMAP_FOREACH_KEY(d, s, m->subsystem_filter) {
                if (!streq(s, subsystem))
                        continue;

                if (!d || streq_ptr(d, devtype))
                        return true;
        }

        return false;
}

static bool check_tag_filter(sd_device_monitor *m, sd_device *device) {
        const char *tag;

        assert(m);
        assert(device);

        if (set_isempty(m->tag_filter))
                return true;

        SET_FOREACH(tag, m->tag_filter)
                if (sd_device_has_tag(device, tag) > 0)
                        return true;

        return false;
}

static int passes_filter(sd_device_monitor *m, sd_device *device) {
        int r;

        assert(m);
        assert(device);

        r = check_subsystem_filter(m, device);
        if (r <= 0)
                return r;

        if (!check_tag_filter(m, device))
                return false;

        if (!device_match_sysattr(device, m->match_sysattr_filter, m->nomatch_sysattr_filter))
                return false;

        return device_match_parent(device, m->match_parent_filter, m->nomatch_parent_filter);
}

int device_monitor_receive_device(sd_device_monitor *m, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        union {
                monitor_netlink_header nlh;
                char raw[8192];
        } buf;
        struct iovec iov = {
                .iov_base = &buf,
                .iov_len = sizeof(buf)
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
        union sockaddr_union snl;
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_name = &snl,
                .msg_namelen = sizeof(snl),
        };
        struct cmsghdr *cmsg;
        struct ucred *cred;
        ssize_t buflen, bufpos;
        bool is_initialized = false;
        int r;

        assert(m);
        assert(ret);

        buflen = recvmsg(m->sock, &smsg, 0);
        if (buflen < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        log_debug_errno(errno, "sd-device-monitor: Failed to receive message: %m");
                return -errno;
        }

        if (buflen < 32 || (smsg.msg_flags & MSG_TRUNC))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "sd-device-monitor: Invalid message length.");

        if (snl.nl.nl_groups == MONITOR_GROUP_NONE) {
                /* unicast message, check if we trust the sender */
                if (m->snl_trusted_sender.nl.nl_pid == 0 ||
                    snl.nl.nl_pid != m->snl_trusted_sender.nl.nl_pid)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Unicast netlink message ignored.");

        } else if (snl.nl.nl_groups == MONITOR_GROUP_KERNEL) {
                if (snl.nl.nl_pid > 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Multicast kernel netlink message from PID %"PRIu32" ignored.", snl.nl.nl_pid);
        }

        cmsg = CMSG_FIRSTHDR(&smsg);
        if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS)
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "sd-device-monitor: No sender credentials received, message ignored.");

        cred = (struct ucred*) CMSG_DATA(cmsg);
        if (cred->uid != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "sd-device-monitor: Sender uid="UID_FMT", message ignored.", cred->uid);

        if (streq(buf.raw, "libudev")) {
                /* udev message needs proper version magic */
                if (buf.nlh.magic != htobe32(UDEV_MONITOR_MAGIC))
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message signature (%x != %x)",
                                               buf.nlh.magic, htobe32(UDEV_MONITOR_MAGIC));

                if (buf.nlh.properties_off+32 > (size_t) buflen)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message length (%u > %zd)",
                                               buf.nlh.properties_off+32, buflen);

                bufpos = buf.nlh.properties_off;

                /* devices received from udev are always initialized */
                is_initialized = true;

        } else {
                /* kernel message with header */
                bufpos = strlen(buf.raw) + 1;
                if ((size_t) bufpos < sizeof("a@/d") || bufpos >= buflen)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message length");

                /* check message header */
                if (!strstr(buf.raw, "@/"))
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message header");
        }

        r = device_new_from_nulstr(&device, (uint8_t*) &buf.raw[bufpos], buflen - bufpos);
        if (r < 0)
                return log_debug_errno(r, "sd-device-monitor: Failed to create device from received message: %m");

        if (is_initialized)
                device_set_is_initialized(device);

        /* Skip device, if it does not pass the current filter */
        r = passes_filter(m, device);
        if (r < 0)
                return log_device_debug_errno(device, r, "sd-device-monitor: Failed to check received device passing filter: %m");
        if (r == 0)
                log_device_debug(device, "sd-device-monitor: Received device does not pass filter, ignoring");
        else
                *ret = TAKE_PTR(device);

        return r;
}

int device_monitor_enable_receiving(sd_device_monitor *m) {
        int r;

        assert(m);

        r = sd_device_monitor_filter_update(m);
        if (r < 0)
                return log_debug_errno(r, "sd-device-monitor: Failed to update filter: %m");

        if (!m->bound) {
                /* enable receiving of sender credentials */
                r = setsockopt_int(m->sock, SOL_SOCKET, SO_PASSCRED, true);
                if (r < 0)
                        return log_debug_errno(r, "sd-device-monitor: Failed to set socket option SO_PASSCRED: %m");

                if (bind(m->sock, &m->snl.sa, sizeof(struct sockaddr_nl)) < 0)
                        return log_debug_errno(errno, "sd-device-monitor: Failed to bind monitoring socket: %m");

                m->bound = true;

                r = monitor_set_nl_address(m);
                if (r < 0)
                        return log_debug_errno(r, "sd-device-monitor: Failed to set address: %m");
        }

        return 0;
}

int device_monitor_allow_unicast_sender(sd_device_monitor *m, sd_device_monitor *sender) {
        assert(m);
        assert(sender);

        m->snl_trusted_sender.nl.nl_pid = sender->snl.nl.nl_pid;
        return 0;
}

int device_monitor_disconnect(sd_device_monitor *m) {
        assert(m);

        m->sock = safe_close(m->sock);
        return 0;
}

int device_monitor_get_fd(sd_device_monitor *m) {
        assert(m);

        return m->sock;
}

int device_monitor_new_full(sd_device_monitor **ret, MonitorNetlinkGroup group, int fd) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_close_ int sock = -1;
        int r;

        assert(group >= 0 && group < _MONITOR_NETLINK_GROUP_MAX);
        assert_return(ret, -EINVAL);

        if (group == MONITOR_GROUP_UDEV &&
            access("/run/udev/control", F_OK) < 0 &&
            dev_is_devtmpfs() <= 0) {

                /*
                 * We do not support subscribing to uevents if no instance of
                 * udev is running. Uevents would otherwise broadcast the
                 * processing data of the host into containers, which is not
                 * desired.
                 *
                 * Containers will currently not get any udev uevents, until
                 * a supporting infrastructure is available.
                 *
                 * We do not set a netlink multicast group here, so the socket
                 * will not receive any messages.
                 */

                log_debug("sd-device-monitor: The udev service seems not to be active, disabling the monitor");
                group = MONITOR_GROUP_NONE;
        }

        if (fd < 0) {
                sock = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
                if (sock < 0)
                        return log_debug_errno(errno, "sd-device-monitor: Failed to create socket: %m");
        }

        m = new(sd_device_monitor, 1);
        if (!m)
                return -ENOMEM;

        *m = (sd_device_monitor) {
                .n_ref = 1,
                .sock = fd >= 0 ? fd : TAKE_FD(sock),
                .bound = fd >= 0,
                .snl.nl.nl_family = AF_NETLINK,
                .snl.nl.nl_groups = group,
        };

        if (fd >= 0) {
                r = monitor_set_nl_address(m);
                if (r < 0) {
                        log_debug_errno(r, "sd-device-monitor: Failed to set netlink address: %m");
                        goto fail;
                }
        }

        if (DEBUG_LOGGING) {
                _cleanup_close_ int netns = -1;

                /* So here's the thing: only AF_NETLINK sockets from the main network namespace will get
                 * hardware events. Let's check if ours is from there, and if not generate a debug message,
                 * since we cannot possibly work correctly otherwise. This is just a safety check to make
                 * things easier to debug. */

                netns = ioctl(m->sock, SIOCGSKNS);
                if (netns < 0)
                        log_debug_errno(errno, "sd-device-monitor: Unable to get network namespace of udev netlink socket, unable to determine if we are in host netns, ignoring: %m");
                else {
                        struct stat a, b;

                        if (fstat(netns, &a) < 0) {
                                r = log_debug_errno(errno, "sd-device-monitor: Failed to stat netns of udev netlink socket: %m");
                                goto fail;
                        }

                        if (stat("/proc/1/ns/net", &b) < 0) {
                                if (ERRNO_IS_PRIVILEGE(errno))
                                        /* If we can't access PID1's netns info due to permissions, it's fine, this is a
                                         * safety check only after all. */
                                        log_debug_errno(errno, "sd-device-monitor: No permission to stat PID1's netns, unable to determine if we are in host netns, ignoring: %m");
                                else
                                        log_debug_errno(errno, "sd-device-monitor: Failed to stat PID1's netns, ignoring: %m");

                        } else if (!stat_inode_same(&a, &b))
                                log_debug("sd-device-monitor: Netlink socket we listen on is not from host netns, we won't see device events.");
                }
        }

        *ret = TAKE_PTR(m);
        return 0;

fail:
        /* Let's unset the socket fd in the monitor object before we destroy it so that the fd passed in is
         * not closed on failure. */
        if (fd >= 0)
                m->sock = -1;

        return r;
}

int device_monitor_send_device(
                sd_device_monitor *m,
                sd_device_monitor *destination,
                sd_device *device) {

        monitor_netlink_header nlh = {
                .prefix = "libudev",
                .magic = htobe32(UDEV_MONITOR_MAGIC),
                .header_size = sizeof nlh,
        };
        struct iovec iov[2] = {
                { .iov_base = &nlh, .iov_len = sizeof nlh },
        };
        struct msghdr smsg = {
                .msg_iov = iov,
                .msg_iovlen = 2,
        };
        /* default destination for sending */
        union sockaddr_union default_destination = {
                .nl.nl_family = AF_NETLINK,
                .nl.nl_groups = MONITOR_GROUP_UDEV,
        };
        uint64_t tag_bloom_bits;
        const char *buf, *val;
        ssize_t count;
        size_t blen;
        int r;

        assert(m);
        assert(device);

        r = device_get_properties_nulstr(device, (const uint8_t **) &buf, &blen);
        if (r < 0)
                return log_device_debug_errno(device, r, "sd-device-monitor: Failed to get device properties: %m");
        if (blen < 32)
                log_device_debug_errno(device, SYNTHETIC_ERRNO(EINVAL),
                                       "sd-device-monitor: Length of device property nulstr is too small to contain valid device information");

        /* fill in versioned header */
        r = sd_device_get_subsystem(device, &val);
        if (r < 0)
                return log_device_debug_errno(device, r, "sd-device-monitor: Failed to get device subsystem: %m");
        nlh.filter_subsystem_hash = htobe32(string_hash32(val));

        if (sd_device_get_devtype(device, &val) >= 0)
                nlh.filter_devtype_hash = htobe32(string_hash32(val));

        /* add tag bloom filter */
        tag_bloom_bits = 0;
        FOREACH_DEVICE_TAG(device, val)
                tag_bloom_bits |= string_bloom64(val);

        if (tag_bloom_bits > 0) {
                nlh.filter_tag_bloom_hi = htobe32(tag_bloom_bits >> 32);
                nlh.filter_tag_bloom_lo = htobe32(tag_bloom_bits & 0xffffffff);
        }

        /* add properties list */
        nlh.properties_off = iov[0].iov_len;
        nlh.properties_len = blen;
        iov[1] = IOVEC_MAKE((char*) buf, blen);

        /*
         * Use custom address for target, or the default one.
         *
         * If we send to a multicast group, we will get
         * ECONNREFUSED, which is expected.
         */
        smsg.msg_name = destination ? &destination->snl : &default_destination;
        smsg.msg_namelen = sizeof(struct sockaddr_nl);
        count = sendmsg(m->sock, &smsg, 0);
        if (count < 0) {
                if (!destination && errno == ECONNREFUSED) {
                        log_device_debug(device, "sd-device-monitor: Passed to netlink monitor");
                        return 0;
                } else
                        return log_device_debug_errno(device, errno, "sd-device-monitor: Failed to send device to netlink monitor: %m");
        }

        log_device_debug(device, "sd-device-monitor: Passed %zi byte to netlink monitor", count);
        return count;
}
