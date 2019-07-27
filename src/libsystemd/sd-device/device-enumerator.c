/* SPDX-License-Identifier: LGPL-2.1+ */

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
        _DEVICE_ENUMERATION_TYPE_INVALID = -1,
} DeviceEnumerationType;

struct sd_device_enumerator {
        unsigned n_ref;

        DeviceEnumerationType type;
        sd_device **devices;
        size_t n_devices, n_allocated, current_device_index;
        bool scan_uptodate;

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

static sd_device_enumerator *device_enumerator_free(sd_device_enumerator *enumerator) {
        size_t i;

        assert(enumerator);

        for (i = 0; i < enumerator->n_devices; i++)
                sd_device_unref(enumerator->devices[i]);

        free(enumerator->devices);
        set_free_free(enumerator->match_subsystem);
        set_free_free(enumerator->nomatch_subsystem);
        hashmap_free_free_free(enumerator->match_sysattr);
        hashmap_free_free_free(enumerator->nomatch_sysattr);
        hashmap_free_free_free(enumerator->match_property);
        set_free_free(enumerator->match_sysname);
        set_free_free(enumerator->match_tag);
        set_free_free(enumerator->match_parent);

        return mfree(enumerator);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device_enumerator, sd_device_enumerator, device_enumerator_free);

_public_ int sd_device_enumerator_add_match_subsystem(sd_device_enumerator *enumerator, const char *subsystem, int match) {
        Set **set;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(subsystem, -EINVAL);

        if (match)
                set = &enumerator->match_subsystem;
        else
                set = &enumerator->nomatch_subsystem;

        r = set_ensure_allocated(set, NULL);
        if (r < 0)
                return r;

        r = set_put_strdup(*set, subsystem);
        if (r < 0)
                return r;

        enumerator->scan_uptodate = false;

        return 0;
}

_public_ int sd_device_enumerator_add_match_sysattr(sd_device_enumerator *enumerator, const char *_sysattr, const char *_value, int match) {
        _cleanup_free_ char *sysattr = NULL, *value = NULL;
        Hashmap **hashmap;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(_sysattr, -EINVAL);

        if (match)
                hashmap = &enumerator->match_sysattr;
        else
                hashmap = &enumerator->nomatch_sysattr;

        r = hashmap_ensure_allocated(hashmap, NULL);
        if (r < 0)
                return r;

        sysattr = strdup(_sysattr);
        if (!sysattr)
                return -ENOMEM;

        if (_value) {
                value = strdup(_value);
                if (!value)
                        return -ENOMEM;
        }

        r = hashmap_put(*hashmap, sysattr, value);
        if (r < 0)
                return r;

        sysattr = NULL;
        value = NULL;

        enumerator->scan_uptodate = false;

        return 0;
}

_public_ int sd_device_enumerator_add_match_property(sd_device_enumerator *enumerator, const char *_property, const char *_value) {
        _cleanup_free_ char *property = NULL, *value = NULL;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(_property, -EINVAL);

        r = hashmap_ensure_allocated(&enumerator->match_property, NULL);
        if (r < 0)
                return r;

        property = strdup(_property);
        if (!property)
                return -ENOMEM;

        if (_value) {
                value = strdup(_value);
                if (!value)
                        return -ENOMEM;
        }

        r = hashmap_put(enumerator->match_property, property, value);
        if (r < 0)
                return r;

        property = NULL;
        value = NULL;

        enumerator->scan_uptodate = false;

        return 0;
}

_public_ int sd_device_enumerator_add_match_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(sysname, -EINVAL);

        r = set_ensure_allocated(&enumerator->match_sysname, NULL);
        if (r < 0)
                return r;

        r = set_put_strdup(enumerator->match_sysname, sysname);
        if (r < 0)
                return r;

        enumerator->scan_uptodate = false;

        return 0;
}

_public_ int sd_device_enumerator_add_match_tag(sd_device_enumerator *enumerator, const char *tag) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(tag, -EINVAL);

        r = set_ensure_allocated(&enumerator->match_tag, NULL);
        if (r < 0)
                return r;

        r = set_put_strdup(enumerator->match_tag, tag);
        if (r < 0)
                return r;

        enumerator->scan_uptodate = false;

        return 0;
}

static void device_enumerator_clear_match_parent(sd_device_enumerator *enumerator) {
        if (!enumerator)
                return;

        set_clear_free(enumerator->match_parent);
}

int device_enumerator_add_match_parent_incremental(sd_device_enumerator *enumerator, sd_device *parent) {
        const char *path;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(parent, -EINVAL);

        r = sd_device_get_syspath(parent, &path);
        if (r < 0)
                return r;

        r = set_ensure_allocated(&enumerator->match_parent, NULL);
        if (r < 0)
                return r;

        r = set_put_strdup(enumerator->match_parent, path);
        if (r < 0)
                return r;

        enumerator->scan_uptodate = false;

        return 0;
}

_public_ int sd_device_enumerator_add_match_parent(sd_device_enumerator *enumerator, sd_device *parent) {
        device_enumerator_clear_match_parent(enumerator);
        return device_enumerator_add_match_parent_incremental(enumerator, parent);
}

_public_ int sd_device_enumerator_allow_uninitialized(sd_device_enumerator *enumerator) {
        assert_return(enumerator, -EINVAL);

        enumerator->match_allow_uninitialized = true;

        enumerator->scan_uptodate = false;

        return 0;
}

int device_enumerator_add_match_is_initialized(sd_device_enumerator *enumerator) {
        assert_return(enumerator, -EINVAL);

        enumerator->match_allow_uninitialized = false;

        enumerator->scan_uptodate = false;

        return 0;
}

static int device_compare(sd_device * const *_a, sd_device * const *_b) {
        sd_device *a = *(sd_device **)_a, *b = *(sd_device **)_b;
        const char *devpath_a, *devpath_b, *sound_a;
        bool delay_a, delay_b;
        int r;

        assert_se(sd_device_get_devpath(a, &devpath_a) >= 0);
        assert_se(sd_device_get_devpath(b, &devpath_b) >= 0);

        sound_a = strstr(devpath_a, "/sound/card");
        if (sound_a) {
                /* For sound cards the control device must be enumerated last to
                 * make sure it's the final device node that gets ACLs applied.
                 * Applications rely on this fact and use ACL changes on the
                 * control node as an indicator that the ACL change of the
                 * entire sound card completed. The kernel makes this guarantee
                 * when creating those devices, and hence we should too when
                 * enumerating them. */
                sound_a += STRLEN("/sound/card");
                sound_a = strchr(sound_a, '/');

                if (sound_a) {
                        unsigned prefix_len;

                        prefix_len = sound_a - devpath_a;

                        if (strncmp(devpath_a, devpath_b, prefix_len) == 0) {
                                const char *sound_b;

                                sound_b = devpath_b + prefix_len;

                                if (startswith(sound_a, "/controlC") &&
                                    !startswith(sound_b, "/contolC"))
                                        return 1;

                                if (!startswith(sound_a, "/controlC") &&
                                    startswith(sound_b, "/controlC"))
                                        return -1;
                        }
                }
        }

        /* md and dm devices are enumerated after all other devices */
        delay_a = strstr(devpath_a, "/block/md") || strstr(devpath_a, "/block/dm-");
        delay_b = strstr(devpath_b, "/block/md") || strstr(devpath_b, "/block/dm-");
        r = CMP(delay_a, delay_b);
        if (r != 0)
                return r;

        return strcmp(devpath_a, devpath_b);
}

int device_enumerator_add_device(sd_device_enumerator *enumerator, sd_device *device) {
        assert_return(enumerator, -EINVAL);
        assert_return(device, -EINVAL);

        if (!GREEDY_REALLOC(enumerator->devices, enumerator->n_allocated, enumerator->n_devices + 1))
                return -ENOMEM;

        enumerator->devices[enumerator->n_devices++] = sd_device_ref(device);

        return 0;
}

static bool match_sysattr_value(sd_device *device, const char *sysattr, const char *match_value) {
        const char *value;
        int r;

        assert(device);
        assert(sysattr);

        r = sd_device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return false;

        if (!match_value)
                return true;

        if (fnmatch(match_value, value, 0) == 0)
                return true;

        return false;
}

static bool match_sysattr(sd_device_enumerator *enumerator, sd_device *device) {
        const char *sysattr;
        const char *value;
        Iterator i;

        assert(enumerator);
        assert(device);

        HASHMAP_FOREACH_KEY(value, sysattr, enumerator->nomatch_sysattr, i)
                if (match_sysattr_value(device, sysattr, value))
                        return false;

        HASHMAP_FOREACH_KEY(value, sysattr, enumerator->match_sysattr, i)
                if (!match_sysattr_value(device, sysattr, value))
                        return false;

        return true;
}

static bool match_property(sd_device_enumerator *enumerator, sd_device *device) {
        const char *property;
        const char *value;
        Iterator i;

        assert(enumerator);
        assert(device);

        if (hashmap_isempty(enumerator->match_property))
                return true;

        HASHMAP_FOREACH_KEY(value, property, enumerator->match_property, i) {
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
        Iterator i;

        assert(enumerator);
        assert(device);

        SET_FOREACH(tag, enumerator->match_tag, i)
                if (!sd_device_has_tag(device, tag))
                        return false;

        return true;
}

static bool match_parent(sd_device_enumerator *enumerator, sd_device *device) {
        const char *syspath_parent, *syspath;
        Iterator i;

        assert(enumerator);
        assert(device);

        if (set_isempty(enumerator->match_parent))
                return true;

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);

        SET_FOREACH(syspath_parent, enumerator->match_parent, i)
                if (path_startswith(syspath, syspath_parent))
                        return true;

        return false;
}

static bool match_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        const char *sysname_match;
        Iterator i;

        assert(enumerator);
        assert(sysname);

        if (set_isempty(enumerator->match_sysname))
                return true;

        SET_FOREACH(sysname_match, enumerator->match_sysname, i)
                if (fnmatch(sysname_match, sysname, 0) == 0)
                        return true;

        return false;
}

static int enumerator_scan_dir_and_add_devices(sd_device_enumerator *enumerator, const char *basedir, const char *subdir1, const char *subdir2) {
        _cleanup_closedir_ DIR *dir = NULL;
        char *path;
        struct dirent *dent;
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
                return -errno;

        FOREACH_DIRENT_ALL(dent, dir, return -errno) {
                _cleanup_(sd_device_unrefp) sd_device *device = NULL;
                char syspath[strlen(path) + 1 + strlen(dent->d_name) + 1];
                int initialized, k;

                if (dent->d_name[0] == '.')
                        continue;

                if (!match_sysname(enumerator, dent->d_name))
                        continue;

                (void) sprintf(syspath, "%s%s", path, dent->d_name);

                k = sd_device_new_from_syspath(&device, syspath);
                if (k < 0) {
                        if (k != -ENODEV)
                                /* this is necessarily racey, so ignore missing devices */
                                r = k;

                        continue;
                }

                initialized = sd_device_get_is_initialized(device);
                if (initialized < 0) {
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

                if (!match_parent(enumerator, device))
                        continue;

                if (!match_tag(enumerator, device))
                        continue;

                if (!match_property(enumerator, device))
                        continue;

                if (!match_sysattr(enumerator, device))
                        continue;

                k = device_enumerator_add_device(enumerator, device);
                if (k < 0)
                        r = k;
        }

        return r;
}

static bool match_subsystem(sd_device_enumerator *enumerator, const char *subsystem) {
        const char *subsystem_match;
        Iterator i;

        assert(enumerator);

        if (!subsystem)
                return false;

        SET_FOREACH(subsystem_match, enumerator->nomatch_subsystem, i)
                if (fnmatch(subsystem_match, subsystem, 0) == 0)
                        return false;

        if (set_isempty(enumerator->match_subsystem))
                return true;

        SET_FOREACH(subsystem_match, enumerator->match_subsystem, i)
                if (fnmatch(subsystem_match, subsystem, 0) == 0)
                        return true;

        return false;
}

static int enumerator_scan_dir(sd_device_enumerator *enumerator, const char *basedir, const char *subdir, const char *subsystem) {
        _cleanup_closedir_ DIR *dir = NULL;
        char *path;
        struct dirent *dent;
        int r = 0;

        path = strjoina("/sys/", basedir);

        dir = opendir(path);
        if (!dir)
                return -errno;

        log_debug("sd-device-enumerator: Scanning %s", path);

        FOREACH_DIRENT_ALL(dent, dir, return -errno) {
                int k;

                if (dent->d_name[0] == '.')
                        continue;

                if (!match_subsystem(enumerator, subsystem ? : dent->d_name))
                        continue;

                k = enumerator_scan_dir_and_add_devices(enumerator, basedir, dent->d_name, subdir);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int enumerator_scan_devices_tag(sd_device_enumerator *enumerator, const char *tag) {
        _cleanup_closedir_ DIR *dir = NULL;
        char *path;
        struct dirent *dent;
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

        FOREACH_DIRENT_ALL(dent, dir, return -errno) {
                _cleanup_(sd_device_unrefp) sd_device *device = NULL;
                const char *subsystem, *sysname;
                int k;

                if (dent->d_name[0] == '.')
                        continue;

                k = sd_device_new_from_device_id(&device, dent->d_name);
                if (k < 0) {
                        if (k != -ENODEV)
                                /* this is necessarily racy, so ignore missing devices */
                                r = k;

                        continue;
                }

                k = sd_device_get_subsystem(device, &subsystem);
                if (k < 0) {
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

                if (!match_parent(enumerator, device))
                        continue;

                if (!match_property(enumerator, device))
                        continue;

                if (!match_sysattr(enumerator, device))
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
        Iterator i;
        int r = 0;

        assert(enumerator);

        SET_FOREACH(tag, enumerator->match_tag, i) {
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

        if (!match_sysattr(enumerator, device))
                return 0;

        r = device_enumerator_add_device(enumerator, device);
        if (r < 0)
                return r;

        return 1;
}

static int parent_crawl_children(sd_device_enumerator *enumerator, const char *path, unsigned maxdepth) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *dent;
        int r = 0;

        dir = opendir(path);
        if (!dir)
                return log_debug_errno(errno, "sd-device-enumerator: Failed to open parent directory %s: %m", path);

        FOREACH_DIRENT_ALL(dent, dir, return -errno) {
                _cleanup_free_ char *child = NULL;
                int k;

                if (dent->d_name[0] == '.')
                        continue;

                if (dent->d_type != DT_DIR)
                        continue;

                child = path_join(path, dent->d_name);
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
        Iterator i;

        SET_FOREACH(path, enumerator->match_parent, i) {
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
        int r = 0;

        log_debug("sd-device-enumerator: Scan all dirs");

        if (access("/sys/subsystem", F_OK) >= 0) {
                /* we have /subsystem/, forget all the old stuff */
                r = enumerator_scan_dir(enumerator, "subsystem", "devices", NULL);
                if (r < 0)
                        return log_debug_errno(r, "sd-device-enumerator: Failed to scan /sys/subsystem: %m");
        } else {
                int k;

                k = enumerator_scan_dir(enumerator, "bus", "devices", NULL);
                if (k < 0) {
                        log_debug_errno(k, "sd-device-enumerator: Failed to scan /sys/bus: %m");
                        r = k;
                }

                k = enumerator_scan_dir(enumerator, "class", NULL, NULL);
                if (k < 0) {
                        log_debug_errno(k, "sd-device-enumerator: Failed to scan /sys/class: %m");
                        r = k;
                }
        }

        return r;
}

static void device_enumerator_dedup_devices(sd_device_enumerator *enumerator) {
        sd_device **a, **b, **end;

        assert(enumerator);

        if (enumerator->n_devices <= 1)
                return;

        a = enumerator->devices + 1;
        b = enumerator->devices;
        end = enumerator->devices + enumerator->n_devices;

        for (; a < end; a++) {
                const char *devpath_a, *devpath_b;

                assert_se(sd_device_get_devpath(*a, &devpath_a) >= 0);
                assert_se(sd_device_get_devpath(*b, &devpath_b) >= 0);

                if (path_equal(devpath_a, devpath_b))
                        sd_device_unref(*a);
                else
                        *(++b) = *a;
        }

        enumerator->n_devices = b - enumerator->devices + 1;
}

int device_enumerator_scan_devices(sd_device_enumerator *enumerator) {
        int r = 0, k;
        size_t i;

        assert(enumerator);

        if (enumerator->scan_uptodate &&
            enumerator->type == DEVICE_ENUMERATION_TYPE_DEVICES)
                return 0;

        for (i = 0; i < enumerator->n_devices; i++)
                sd_device_unref(enumerator->devices[i]);

        enumerator->n_devices = 0;

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

        typesafe_qsort(enumerator->devices, enumerator->n_devices, device_compare);
        device_enumerator_dedup_devices(enumerator);

        enumerator->scan_uptodate = true;
        enumerator->type = DEVICE_ENUMERATION_TYPE_DEVICES;

        return r;
}

_public_ sd_device *sd_device_enumerator_get_device_first(sd_device_enumerator *enumerator) {
        int r;

        assert_return(enumerator, NULL);

        r = device_enumerator_scan_devices(enumerator);
        if (r < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

_public_ sd_device *sd_device_enumerator_get_device_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_DEVICES ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}

int device_enumerator_scan_subsystems(sd_device_enumerator *enumerator) {
        const char *subsysdir;
        int r = 0, k;
        size_t i;

        assert(enumerator);

        if (enumerator->scan_uptodate &&
            enumerator->type == DEVICE_ENUMERATION_TYPE_SUBSYSTEMS)
                return 0;

        for (i = 0; i < enumerator->n_devices; i++)
                sd_device_unref(enumerator->devices[i]);

        enumerator->n_devices = 0;

        /* modules */
        if (match_subsystem(enumerator, "module")) {
                k = enumerator_scan_dir_and_add_devices(enumerator, "module", NULL, NULL);
                if (k < 0) {
                        log_debug_errno(k, "sd-device-enumerator: Failed to scan modules: %m");
                        r = k;
                }
        }

        if (access("/sys/subsystem", F_OK) >= 0)
                subsysdir = "subsystem";
        else
                subsysdir = "bus";

        /* subsystems (only buses support coldplug) */
        if (match_subsystem(enumerator, "subsystem")) {
                k = enumerator_scan_dir_and_add_devices(enumerator, subsysdir, NULL, NULL);
                if (k < 0) {
                        log_debug_errno(k, "sd-device-enumerator: Failed to scan subsystems: %m");
                        r = k;
                }
        }

        /* subsystem drivers */
        if (match_subsystem(enumerator, "drivers")) {
                k = enumerator_scan_dir(enumerator, subsysdir, "drivers", "drivers");
                if (k < 0) {
                        log_debug_errno(k, "sd-device-enumerator: Failed to scan drivers: %m");
                        r = k;
                }
        }

        typesafe_qsort(enumerator->devices, enumerator->n_devices, device_compare);
        device_enumerator_dedup_devices(enumerator);

        enumerator->scan_uptodate = true;
        enumerator->type = DEVICE_ENUMERATION_TYPE_SUBSYSTEMS;

        return r;
}

_public_ sd_device *sd_device_enumerator_get_subsystem_first(sd_device_enumerator *enumerator) {
        int r;

        assert_return(enumerator, NULL);

        r = device_enumerator_scan_subsystems(enumerator);
        if (r < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

_public_ sd_device *sd_device_enumerator_get_subsystem_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_SUBSYSTEMS ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}

sd_device *device_enumerator_get_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

sd_device *device_enumerator_get_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}

sd_device **device_enumerator_get_devices(sd_device_enumerator *enumerator, size_t *ret_n_devices) {
        assert(enumerator);
        assert(ret_n_devices);

        if (!enumerator->scan_uptodate)
                return NULL;

        *ret_n_devices = enumerator->n_devices;
        return enumerator->devices;
}
