/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "device-enumerator-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"

#define DEVICE_ENUMERATE_MAX_DEPTH 256

typedef enum DeviceEnumerationType {
        DEVICE_ENUMERATION_TYPE_DEVICES,
        DEVICE_ENUMERATION_TYPE_SUBSYSTEMS,
        _DEVICE_ENUMERATION_TYPE_MAX,
        _DEVICE_ENUMERATION_TYPE_INVALID = -EINVAL,
} DeviceEnumerationType;

struct sd_device_enumerator {
        unsigned n_ref;

        DeviceEnumerationType type;
        Hashmap *devices_by_syspath;
        sd_device **devices;
        size_t n_devices, current_device_index;
        bool scan_uptodate;
        bool sorted;

        char **prioritized_subsystems;
        Set *match_subsystem;
        Set *nomatch_subsystem;
        Hashmap *match_sysattr;
        Hashmap *nomatch_sysattr;
        Hashmap *match_property;
        Set *match_sysname;
        Set *match_tag;
        Set *match_parent;
        bool match_allow_uninitialized;
};

_public_ int sd_device_enumerator_new(sd_device_enumerator **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *enumerator = NULL;

        assert(ret);

        enumerator = new(sd_device_enumerator, 1);
        if (!enumerator)
                return -ENOMEM;

        *enumerator = (sd_device_enumerator) {
                .n_ref = 1,
                .type = _DEVICE_ENUMERATION_TYPE_INVALID,
        };

        *ret = TAKE_PTR(enumerator);

        return 0;
}

static void device_unref_many(sd_device **devices, size_t n) {
        assert(devices || n == 0);

        for (size_t i = 0; i < n; i++)
                sd_device_unref(devices[i]);
}

static void device_enumerator_unref_devices(sd_device_enumerator *enumerator) {
        assert(enumerator);

        hashmap_clear_with_destructor(enumerator->devices_by_syspath, sd_device_unref);
        device_unref_many(enumerator->devices, enumerator->n_devices);
        enumerator->devices = mfree(enumerator->devices);
        enumerator->n_devices = 0;
}

static sd_device_enumerator *device_enumerator_free(sd_device_enumerator *enumerator) {
        assert(enumerator);

        device_enumerator_unref_devices(enumerator);

        hashmap_free(enumerator->devices_by_syspath);
        strv_free(enumerator->prioritized_subsystems);
        set_free(enumerator->match_subsystem);
        set_free(enumerator->nomatch_subsystem);
        hashmap_free(enumerator->match_sysattr);
        hashmap_free(enumerator->nomatch_sysattr);
        hashmap_free(enumerator->match_property);
        set_free(enumerator->match_sysname);
        set_free(enumerator->match_tag);
        set_free(enumerator->match_parent);

        return mfree(enumerator);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device_enumerator, sd_device_enumerator, device_enumerator_free);

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

_public_ int sd_device_enumerator_add_match_subsystem(sd_device_enumerator *enumerator, const char *subsystem, int match) {
        Set **set;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(subsystem, -EINVAL);

        if (match)
                set = &enumerator->match_subsystem;
        else
                set = &enumerator->nomatch_subsystem;

        r = set_put_strdup(set, subsystem);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_sysattr(sd_device_enumerator *enumerator, const char *sysattr, const char *value, int match) {
        Hashmap **hashmap;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(sysattr, -EINVAL);

        if (match)
                hashmap = &enumerator->match_sysattr;
        else
                hashmap = &enumerator->nomatch_sysattr;

        /* Do not use string_has_ops_free_free or hashmap_put_strdup() here, as this may be called
         * multiple times with the same sysattr but different value. */
        r = hashmap_put_strdup_full(hashmap, &trivial_hash_ops_free_free, sysattr, value);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_property(sd_device_enumerator *enumerator, const char *property, const char *value) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(property, -EINVAL);

        /* Do not use string_has_ops_free_free or hashmap_put_strdup() here, as this may be called
         * multiple times with the same property but different value. */
        r = hashmap_put_strdup_full(&enumerator->match_property, &trivial_hash_ops_free_free, property, value);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(sysname, -EINVAL);

        r = set_put_strdup(&enumerator->match_sysname, sysname);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_tag(sd_device_enumerator *enumerator, const char *tag) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(tag, -EINVAL);

        r = set_put_strdup(&enumerator->match_tag, tag);
        if (r <= 0)
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

_public_ int sd_device_enumerator_add_match_parent(sd_device_enumerator *enumerator, sd_device *parent) {
        assert_return(enumerator, -EINVAL);
        assert_return(parent, -EINVAL);

        set_clear(enumerator->match_parent);

        return device_enumerator_add_match_parent_incremental(enumerator, parent);
}

_public_ int sd_device_enumerator_allow_uninitialized(sd_device_enumerator *enumerator) {
        assert_return(enumerator, -EINVAL);

        enumerator->match_allow_uninitialized = true;

        enumerator->scan_uptodate = false;

        return 1;
}

int device_enumerator_add_match_is_initialized(sd_device_enumerator *enumerator) {
        assert_return(enumerator, -EINVAL);

        enumerator->match_allow_uninitialized = false;

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

        return strcmp(devpath_a, devpath_b);
}

static int enumerator_sort_devices(sd_device_enumerator *enumerator) {
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
        const char *sysname_match;

        assert(enumerator);
        assert(sysname);

        if (set_isempty(enumerator->match_sysname))
                return true;

        SET_FOREACH(sysname_match, enumerator->match_sysname)
                if (fnmatch(sysname_match, sysname, 0) == 0)
                        return true;

        return false;
}

static int enumerator_scan_dir_and_add_devices(sd_device_enumerator *enumerator, const char *basedir, const char *subdir1, const char *subdir2) {
        _cleanup_closedir_ DIR *dir = NULL;
        char *path;
        int r = 0;

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
                int initialized, k;

                if (de->d_name[0] == '.')
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

                initialized = sd_device_get_is_initialized(device);
                if (initialized < 0) {
                        if (initialized != -ENOENT)
                                /* this is necessarily racey, so ignore missing devices */
                                r = initialized;

                        continue;
                }

                /*
                 * All devices with a device node or network interfaces
                 * possibly need udev to adjust the device node permission
                 * or context, or rename the interface before it can be
                 * reliably used from other processes.
                 *
                 * For now, we can only check these types of devices, we
                 * might not store a database, and have no way to find out
                 * for all other types of devices.
                 */
                if (!enumerator->match_allow_uninitialized &&
                    !initialized &&
                    (sd_device_get_devnum(device, NULL) >= 0 ||
                     sd_device_get_ifindex(device, NULL) >= 0))
                        continue;

                if (!device_match_parent(device, enumerator->match_parent, NULL))
                        continue;

                if (!match_tag(enumerator, device))
                        continue;

                if (!match_property(enumerator, device))
                        continue;

                if (!device_match_sysattr(device, enumerator->match_sysattr, enumerator->nomatch_sysattr))
                        continue;

                k = device_enumerator_add_device(enumerator, device);
                if (k < 0)
                        r = k;
        }

        return r;
}

static bool match_subsystem(sd_device_enumerator *enumerator, const char *subsystem) {
        const char *subsystem_match;

        assert(enumerator);

        if (!subsystem)
                return false;

        SET_FOREACH(subsystem_match, enumerator->nomatch_subsystem)
                if (fnmatch(subsystem_match, subsystem, 0) == 0)
                        return false;

        if (set_isempty(enumerator->match_subsystem))
                return true;

        SET_FOREACH(subsystem_match, enumerator->match_subsystem)
                if (fnmatch(subsystem_match, subsystem, 0) == 0)
                        return true;

        return false;
}

static int enumerator_scan_dir(sd_device_enumerator *enumerator, const char *basedir, const char *subdir, const char *subsystem) {
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

                if (de->d_name[0] == '.')
                        continue;

                if (!match_subsystem(enumerator, subsystem ? : de->d_name))
                        continue;

                k = enumerator_scan_dir_and_add_devices(enumerator, basedir, de->d_name, subdir);
                if (k < 0)
                        r = k;
        }

        return r;
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

static int enumerator_scan_devices_tags(sd_device_enumerator *enumerator) {
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

_public_ sd_device *sd_device_enumerator_get_device_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (device_enumerator_scan_devices(enumerator) < 0)
                return NULL;

        if (enumerator_sort_devices(enumerator) < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

_public_ sd_device *sd_device_enumerator_get_device_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            !enumerator->sorted ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_DEVICES ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
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
                k = enumerator_scan_dir_and_add_devices(enumerator, "module", NULL, NULL);
                if (k < 0)
                        r = log_debug_errno(k, "sd-device-enumerator: Failed to scan modules: %m");
        }

        /* subsystems (only buses support coldplug) */
        if (match_subsystem(enumerator, "subsystem")) {
                k = enumerator_scan_dir_and_add_devices(enumerator, "bus", NULL, NULL);
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

_public_ sd_device *sd_device_enumerator_get_subsystem_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (device_enumerator_scan_subsystems(enumerator) < 0)
                return NULL;

        if (enumerator_sort_devices(enumerator) < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

_public_ sd_device *sd_device_enumerator_get_subsystem_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            !enumerator->sorted ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_SUBSYSTEMS ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}

sd_device *device_enumerator_get_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate)
                return NULL;

        if (enumerator_sort_devices(enumerator) < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

sd_device *device_enumerator_get_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            !enumerator->sorted ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}

sd_device **device_enumerator_get_devices(sd_device_enumerator *enumerator, size_t *ret_n_devices) {
        assert(enumerator);
        assert(ret_n_devices);

        if (!enumerator->scan_uptodate)
                return NULL;

        if (enumerator_sort_devices(enumerator) < 0)
                return NULL;

        *ret_n_devices = enumerator->n_devices;
        return enumerator->devices;
}
