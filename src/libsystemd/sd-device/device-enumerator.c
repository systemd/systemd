/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2014-2015 Tom Gundersen <teg@jklm.no>

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

#include "util.h"
#include "prioq.h"
#include "strv.h"
#include "set.h"

#include "sd-device.h"

#include "device-util.h"
#include "device-enumerator-private.h"

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
        Prioq *devices;
        bool scan_uptodate;

        Set *match_subsystem;
        Set *nomatch_subsystem;
        Hashmap *match_sysattr;
        Hashmap *nomatch_sysattr;
        Hashmap *match_property;
        Set *match_sysname;
        Set *match_tag;
        sd_device *match_parent;
        bool match_allow_uninitialized;
};

_public_ int sd_device_enumerator_new(sd_device_enumerator **ret) {
        _cleanup_device_enumerator_unref_ sd_device_enumerator *enumerator = NULL;

        assert(ret);

        enumerator = new0(sd_device_enumerator, 1);
        if (!enumerator)
                return -ENOMEM;

        enumerator->n_ref = 1;
        enumerator->type = _DEVICE_ENUMERATION_TYPE_INVALID;

        *ret = enumerator;
        enumerator = NULL;

        return 0;
}

_public_ sd_device_enumerator *sd_device_enumerator_ref(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        assert_se((++ enumerator->n_ref) >= 2);

        return enumerator;
}

_public_ sd_device_enumerator *sd_device_enumerator_unref(sd_device_enumerator *enumerator) {
        if (enumerator && (-- enumerator->n_ref) == 0) {
                sd_device *device;

                while ((device = prioq_pop(enumerator->devices)))
                        sd_device_unref(device);

                prioq_free(enumerator->devices);

                set_free_free(enumerator->match_subsystem);
                set_free_free(enumerator->nomatch_subsystem);
                hashmap_free_free_free(enumerator->match_sysattr);
                hashmap_free_free_free(enumerator->nomatch_sysattr);
                hashmap_free_free_free(enumerator->match_property);
                set_free_free(enumerator->match_sysname);
                set_free_free(enumerator->match_tag);
                sd_device_unref(enumerator->match_parent);

                free(enumerator);
        }

        return NULL;
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

_public_ int sd_device_enumerator_add_match_parent(sd_device_enumerator *enumerator, sd_device *parent) {
        assert_return(enumerator, -EINVAL);
        assert_return(parent, -EINVAL);

        sd_device_unref(enumerator->match_parent);
        enumerator->match_parent = sd_device_ref(parent);

        enumerator->scan_uptodate = false;

        return 0;
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

static int device_compare(const void *_a, const void *_b) {
        sd_device *a = (sd_device *)_a, *b = (sd_device *)_b;
        const char *devpath_a, *devpath_b, *sound_a;
        bool delay_a, delay_b;

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
                sound_a += strlen("/sound/card");
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
        if (delay_a != delay_b)
                return delay_a - delay_b;

        return strcmp(devpath_a, devpath_b);
}

int device_enumerator_add_device(sd_device_enumerator *enumerator, sd_device *device) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(device, -EINVAL);

        r = prioq_ensure_allocated(&enumerator->devices, device_compare);
        if (r < 0)
                return r;

        r = prioq_put(enumerator->devices, device, NULL);
        if (r < 0)
                return r;

        sd_device_ref(device);

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
        const char *devpath, *devpath_dev;
        int r;

        assert(enumerator);
        assert(device);

        if (!enumerator->match_parent)
                return true;

        r = sd_device_get_devpath(enumerator->match_parent, &devpath);
        assert(r >= 0);

        r = sd_device_get_devpath(device, &devpath_dev);
        assert(r >= 0);

        return startswith(devpath_dev, devpath);
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
                _cleanup_device_unref_ sd_device *device = NULL;
                char syspath[strlen(path) + 1 + strlen(dent->d_name) + 1];
                dev_t devnum;
                int ifindex, initialized, k;

                if (dent->d_name[0] == '.')
                        continue;

                if (!match_sysname(enumerator, dent->d_name))
                        continue;

                (void)sprintf(syspath, "%s%s", path, dent->d_name);

                k = sd_device_new_from_syspath(&device, syspath);
                if (k < 0) {
                        if (k != -ENODEV)
                                /* this is necessarily racey, so ignore missing devices */
                                r = k;

                        continue;
                }

                k = sd_device_get_devnum(device, &devnum);
                if (k < 0) {
                        r = k;
                        continue;
                }

                k = sd_device_get_ifindex(device, &ifindex);
                if (k < 0) {
                        r = k;
                        continue;
                }

                k = sd_device_get_is_initialized(device, &initialized);
                if (k < 0) {
                        r = k;
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
                    (major(devnum) > 0 || ifindex > 0))
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

        log_debug("  device-enumerator: scanning %s", path);

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
                if (errno == ENOENT)
                        return 0;
                else {
                        log_error("sd-device-enumerator: could not open tags directory %s: %m", path);
                        return -errno;
                }
        }

        /* TODO: filter away subsystems? */

        FOREACH_DIRENT_ALL(dent, dir, return -errno) {
                _cleanup_device_unref_ sd_device *device = NULL;
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
        int r;

        assert(enumerator);

        SET_FOREACH(tag, enumerator->match_tag, i) {
                r = enumerator_scan_devices_tag(enumerator, tag);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int parent_add_child(sd_device_enumerator *enumerator, const char *path) {
        _cleanup_device_unref_ sd_device *device = NULL;
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
        if (!dir) {
                log_debug("sd-device-enumerate: could not open parent directory %s: %m", path);
                return -errno;
        }

        FOREACH_DIRENT_ALL(dent, dir, return -errno) {
                _cleanup_free_ char *child = NULL;
                int k;

                if (dent->d_name[0] == '.')
                        continue;

                if (dent->d_type != DT_DIR)
                        continue;

                child = strjoin(path, "/", dent->d_name, NULL);
                if (!child)
                        return -ENOMEM;

                k = parent_add_child(enumerator, child);
                if (k < 0)
                        r = k;

                if (maxdepth > 0)
                        parent_crawl_children(enumerator, child, maxdepth - 1);
                else
                        log_debug("device-enumerate: max depth reached, %s: ignoring devices", child);
        }

        return r;
}

static int enumerator_scan_devices_children(sd_device_enumerator *enumerator) {
        const char *path;
        int r = 0, k;

        r = sd_device_get_syspath(enumerator->match_parent, &path);
        if (r < 0)
                return r;

        k = parent_add_child(enumerator, path);
        if (k < 0)
                r = k;

        k = parent_crawl_children(enumerator, path, DEVICE_ENUMERATE_MAX_DEPTH);
        if (k < 0)
                r = k;

        return r;
}

static int enumerator_scan_devices_all(sd_device_enumerator *enumerator) {
        int r = 0;

        log_debug("device-enumerator: scan all dirs");

        if (access("/sys/subsystem", F_OK) >= 0) {
                /* we have /subsystem/, forget all the old stuff */
                r = enumerator_scan_dir(enumerator, "subsystem", "devices", NULL);
                if (r < 0)
                        return log_debug_errno(r, "device-enumerator: failed to scan /sys/subsystem: %m");
        } else {
                int k;

                k = enumerator_scan_dir(enumerator, "bus", "devices", NULL);
                if (k < 0) {
                        log_debug_errno(k, "device-enumerator: failed to scan /sys/bus: %m");
                        r = k;
                }

                k = enumerator_scan_dir(enumerator, "class", NULL, NULL);
                if (k < 0) {
                        log_debug_errno(k, "device-enumerator: failed to scan /sys/class: %m");
                        r = k;
                }
        }

        return r;
}

int device_enumerator_scan_devices(sd_device_enumerator *enumerator) {
        sd_device *device;
        int r;

        assert(enumerator);

        if (enumerator->scan_uptodate &&
            enumerator->type == DEVICE_ENUMERATION_TYPE_DEVICES)
                return 0;

        while ((device = prioq_pop(enumerator->devices)))
                sd_device_unref(device);

        if (!set_isempty(enumerator->match_tag)) {
                r = enumerator_scan_devices_tags(enumerator);
                if (r < 0)
                        return r;
        } else if (enumerator->match_parent) {
                r = enumerator_scan_devices_children(enumerator);
                if (r < 0)
                        return r;
        } else {
                r = enumerator_scan_devices_all(enumerator);
                if (r < 0)
                        return r;
        }

        enumerator->scan_uptodate = true;

        return 0;
}

_public_ sd_device *sd_device_enumerator_get_device_first(sd_device_enumerator *enumerator) {
        int r;

        assert_return(enumerator, NULL);

        r = device_enumerator_scan_devices(enumerator);
        if (r < 0)
                return NULL;

        enumerator->type = DEVICE_ENUMERATION_TYPE_DEVICES;

        return prioq_peek(enumerator->devices);
}

_public_ sd_device *sd_device_enumerator_get_device_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_DEVICES)
                return NULL;

        sd_device_unref(prioq_pop(enumerator->devices));

        return prioq_peek(enumerator->devices);
}

int device_enumerator_scan_subsystems(sd_device_enumerator *enumerator) {
        sd_device *device;
        const char *subsysdir;
        int r = 0, k;

        assert(enumerator);

        if (enumerator->scan_uptodate &&
            enumerator->type == DEVICE_ENUMERATION_TYPE_SUBSYSTEMS)
                return 0;

        while ((device = prioq_pop(enumerator->devices)))
                sd_device_unref(device);

        /* modules */
        if (match_subsystem(enumerator, "module")) {
                k = enumerator_scan_dir_and_add_devices(enumerator, "module", NULL, NULL);
                if (k < 0) {
                        log_debug_errno(k, "device-enumerator: failed to scan modules: %m");
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
                        log_debug_errno(k, "device-enumerator: failed to scan subsystems: %m");
                        r = k;
                }
        }

        /* subsystem drivers */
        if (match_subsystem(enumerator, "drivers")) {
                k = enumerator_scan_dir(enumerator, subsysdir, "drivers", "drivers");
                if (k < 0) {
                        log_debug_errno(k, "device-enumerator: failed to scan drivers: %m");
                        r = k;
                }
        }

        enumerator->scan_uptodate = true;

        return r;
}

_public_ sd_device *sd_device_enumerator_get_subsystem_first(sd_device_enumerator *enumerator) {
        int r;

        assert_return(enumerator, NULL);

        r = device_enumerator_scan_subsystems(enumerator);
        if (r < 0)
                return NULL;

        enumerator->type = DEVICE_ENUMERATION_TYPE_SUBSYSTEMS;

        return prioq_peek(enumerator->devices);
}

_public_ sd_device *sd_device_enumerator_get_subsystem_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (enumerator->scan_uptodate ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_SUBSYSTEMS)
                return NULL;

        sd_device_unref(prioq_pop(enumerator->devices));

        return prioq_peek(enumerator->devices);
}

sd_device *device_enumerator_get_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        return prioq_peek(enumerator->devices);
}

sd_device *device_enumerator_get_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        sd_device_unref(prioq_pop(enumerator->devices));

        return prioq_peek(enumerator->devices);
}
