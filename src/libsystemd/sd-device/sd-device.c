/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <net/if.h>
#include <sys/types.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "device-internal.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "set.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "util.h"

int device_new_aux(sd_device **ret) {
        sd_device *device = NULL;

        assert(ret);

        device = new(sd_device, 1);
        if (!device)
                return -ENOMEM;

        *device = (sd_device) {
                .n_ref = 1,
                .watch_handle = -1,
                .devmode = (mode_t) -1,
                .devuid = (uid_t) -1,
                .devgid = (gid_t) -1,
        };

        *ret = device;
        return 0;
}

static sd_device *device_free(sd_device *device) {
        assert(device);

        sd_device_unref(device->parent);
        free(device->syspath);
        free(device->sysname);
        free(device->devtype);
        free(device->devname);
        free(device->subsystem);
        free(device->driver_subsystem);
        free(device->driver);
        free(device->id_filename);
        free(device->properties_strv);
        free(device->properties_nulstr);

        ordered_hashmap_free_free_free(device->properties);
        ordered_hashmap_free_free_free(device->properties_db);
        hashmap_free_free_free(device->sysattr_values);
        set_free_free(device->sysattrs);
        set_free_free(device->tags);
        set_free_free(device->devlinks);

        return mfree(device);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device, sd_device, device_free);

int device_add_property_aux(sd_device *device, const char *_key, const char *_value, bool db) {
        OrderedHashmap **properties;

        assert(device);
        assert(_key);

        if (db)
                properties = &device->properties_db;
        else
                properties = &device->properties;

        if (_value) {
                _cleanup_free_ char *key = NULL, *value = NULL, *old_key = NULL, *old_value = NULL;
                int r;

                r = ordered_hashmap_ensure_allocated(properties, &string_hash_ops);
                if (r < 0)
                        return r;

                key = strdup(_key);
                if (!key)
                        return -ENOMEM;

                value = strdup(_value);
                if (!value)
                        return -ENOMEM;

                old_value = ordered_hashmap_get2(*properties, key, (void**) &old_key);

                r = ordered_hashmap_replace(*properties, key, value);
                if (r < 0)
                        return r;

                key = NULL;
                value = NULL;
        } else {
                _cleanup_free_ char *key = NULL;
                _cleanup_free_ char *value = NULL;

                value = ordered_hashmap_remove2(*properties, _key, (void**) &key);
        }

        if (!db) {
                device->properties_generation++;
                device->properties_buf_outdated = true;
        }

        return 0;
}

int device_add_property_internal(sd_device *device, const char *key, const char *value) {
        return device_add_property_aux(device, key, value, false);
}

int device_set_syspath(sd_device *device, const char *_syspath, bool verify) {
        _cleanup_free_ char *syspath = NULL;
        const char *devpath;
        int r;

        assert(device);
        assert(_syspath);

        /* must be a subdirectory of /sys */
        if (!path_startswith(_syspath, "/sys/")) {
                log_debug("sd-device: Syspath '%s' is not a subdirectory of /sys", _syspath);
                return -EINVAL;
        }

        if (verify) {
                r = chase_symlinks(_syspath, NULL, 0, &syspath);
                if (r == -ENOENT)
                        return -ENODEV; /* the device does not exist (any more?) */
                if (r < 0)
                        return log_debug_errno(r, "sd-device: Failed to get target of '%s': %m", _syspath);

                if (!path_startswith(syspath, "/sys")) {
                        _cleanup_free_ char *real_sys = NULL, *new_syspath = NULL;
                        char *p;

                        /* /sys is a symlink to somewhere sysfs is mounted on? In that case, we convert the path to real sysfs to "/sys". */
                        r = chase_symlinks("/sys", NULL, 0, &real_sys);
                        if (r < 0)
                                return log_debug_errno(r, "sd-device: Failed to chase symlink /sys: %m");

                        p = path_startswith(syspath, real_sys);
                        if (!p) {
                                log_debug("sd-device: Canonicalized path '%s' does not starts with sysfs mount point '%s'", syspath, real_sys);
                                return -ENODEV;
                        }

                        new_syspath = strjoin("/sys/", p);
                        if (!new_syspath)
                                return -ENOMEM;

                        free_and_replace(syspath, new_syspath);
                        path_simplify(syspath, false);
                }

                if (path_startswith(syspath,  "/sys/devices/")) {
                        char *path;

                        /* all 'devices' require an 'uevent' file */
                        path = strjoina(syspath, "/uevent");
                        r = access(path, F_OK);
                        if (r < 0) {
                                if (errno == ENOENT)
                                        /* this is not a valid device */
                                        return -ENODEV;

                                return log_debug_errno(errno, "sd-device: %s does not have an uevent file: %m", syspath);
                        }
                } else {
                        /* everything else just needs to be a directory */
                        if (!is_dir(syspath, false))
                                return -ENODEV;
                }
        } else {
                syspath = strdup(_syspath);
                if (!syspath)
                        return -ENOMEM;
        }

        devpath = syspath + STRLEN("/sys");

        r = device_add_property_internal(device, "DEVPATH", devpath);
        if (r < 0)
                return r;

        free_and_replace(device->syspath, syspath);

        device->devpath = devpath;

        return 0;
}

_public_ int sd_device_new_from_syspath(sd_device **ret, const char *syspath) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(syspath, -EINVAL);

        r = device_new_aux(&device);
        if (r < 0)
                return r;

        r = device_set_syspath(device, syspath, true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(device);

        return 0;
}

_public_ int sd_device_new_from_devnum(sd_device **ret, char type, dev_t devnum) {
        char *syspath;
        char id[DECIMAL_STR_MAX(unsigned) * 2 + 1];

        assert_return(ret, -EINVAL);
        assert_return(IN_SET(type, 'b', 'c'), -EINVAL);

        /* use /sys/dev/{block,char}/<maj>:<min> link */
        snprintf(id, sizeof(id), "%u:%u", major(devnum), minor(devnum));

        syspath = strjoina("/sys/dev/", (type == 'b' ? "block" : "char"), "/", id);

        return sd_device_new_from_syspath(ret, syspath);
}

_public_ int sd_device_new_from_subsystem_sysname(sd_device **ret, const char *subsystem, const char *sysname) {
        char *name, *syspath;
        size_t len = 0;

        assert_return(ret, -EINVAL);
        assert_return(subsystem, -EINVAL);
        assert_return(sysname, -EINVAL);

        if (streq(subsystem, "subsystem")) {
                syspath = strjoina("/sys/subsystem/", sysname);
                if (access(syspath, F_OK) >= 0)
                        return sd_device_new_from_syspath(ret, syspath);

                syspath = strjoina("/sys/bus/", sysname);
                if (access(syspath, F_OK) >= 0)
                        return sd_device_new_from_syspath(ret, syspath);

                syspath = strjoina("/sys/class/", sysname);
                if (access(syspath, F_OK) >= 0)
                        return sd_device_new_from_syspath(ret, syspath);
        } else  if (streq(subsystem, "module")) {
                syspath = strjoina("/sys/module/", sysname);
                if (access(syspath, F_OK) >= 0)
                        return sd_device_new_from_syspath(ret, syspath);
        } else if (streq(subsystem, "drivers")) {
                char subsys[PATH_MAX];
                char *driver;

                strscpy(subsys, sizeof(subsys), sysname);
                driver = strchr(subsys, ':');
                if (driver) {
                        driver[0] = '\0';
                        driver++;

                        syspath = strjoina("/sys/subsystem/", subsys, "/drivers/", driver);
                        if (access(syspath, F_OK) >= 0)
                                return sd_device_new_from_syspath(ret, syspath);

                        syspath = strjoina("/sys/bus/", subsys, "/drivers/", driver);
                        if (access(syspath, F_OK) >= 0)
                                return sd_device_new_from_syspath(ret, syspath);
                }
        }

        /* translate sysname back to sysfs filename */
        name = strdupa(sysname);
        while (name[len] != '\0') {
                if (name[len] == '/')
                        name[len] = '!';

                len++;
        }

        syspath = strjoina("/sys/subsystem/", subsystem, "/devices/", name);
        if (access(syspath, F_OK) >= 0)
                return sd_device_new_from_syspath(ret, syspath);

        syspath = strjoina("/sys/bus/", subsystem, "/devices/", name);
        if (access(syspath, F_OK) >= 0)
                return sd_device_new_from_syspath(ret, syspath);

        syspath = strjoina("/sys/class/", subsystem, "/", name);
        if (access(syspath, F_OK) >= 0)
                return sd_device_new_from_syspath(ret, syspath);

        syspath = strjoina("/sys/firmware/", subsystem, "/", sysname);
        if (access(syspath, F_OK) >= 0)
                return sd_device_new_from_syspath(ret, syspath);

        return -ENODEV;
}

int device_set_devtype(sd_device *device, const char *_devtype) {
        _cleanup_free_ char *devtype = NULL;
        int r;

        assert(device);
        assert(_devtype);

        devtype = strdup(_devtype);
        if (!devtype)
                return -ENOMEM;

        r = device_add_property_internal(device, "DEVTYPE", devtype);
        if (r < 0)
                return r;

        free_and_replace(device->devtype, devtype);

        return 0;
}

int device_set_ifindex(sd_device *device, const char *_ifindex) {
        int ifindex, r;

        assert(device);
        assert(_ifindex);

        r = parse_ifindex(_ifindex, &ifindex);
        if (r < 0)
                return r;

        r = device_add_property_internal(device, "IFINDEX", _ifindex);
        if (r < 0)
                return r;

        device->ifindex = ifindex;

        return 0;
}

int device_set_devname(sd_device *device, const char *_devname) {
        _cleanup_free_ char *devname = NULL;
        int r;

        assert(device);
        assert(_devname);

        if (_devname[0] != '/') {
                r = asprintf(&devname, "/dev/%s", _devname);
                if (r < 0)
                        return -ENOMEM;
        } else {
                devname = strdup(_devname);
                if (!devname)
                        return -ENOMEM;
        }

        r = device_add_property_internal(device, "DEVNAME", devname);
        if (r < 0)
                return r;

        free_and_replace(device->devname, devname);

        return 0;
}

int device_set_devmode(sd_device *device, const char *_devmode) {
        unsigned devmode;
        int r;

        assert(device);
        assert(_devmode);

        r = safe_atou(_devmode, &devmode);
        if (r < 0)
                return r;

        if (devmode > 07777)
                return -EINVAL;

        r = device_add_property_internal(device, "DEVMODE", _devmode);
        if (r < 0)
                return r;

        device->devmode = devmode;

        return 0;
}

int device_set_devnum(sd_device *device, const char *major, const char *minor) {
        unsigned maj = 0, min = 0;
        int r;

        assert(device);
        assert(major);

        r = safe_atou(major, &maj);
        if (r < 0)
                return r;
        if (!maj)
                return 0;

        if (minor) {
                r = safe_atou(minor, &min);
                if (r < 0)
                        return r;
        }

        r = device_add_property_internal(device, "MAJOR", major);
        if (r < 0)
                return r;

        if (minor) {
                r = device_add_property_internal(device, "MINOR", minor);
                if (r < 0)
                        return r;
        }

        device->devnum = makedev(maj, min);

        return 0;
}

static int handle_uevent_line(sd_device *device, const char *key, const char *value, const char **major, const char **minor) {
        int r;

        assert(device);
        assert(key);
        assert(value);
        assert(major);
        assert(minor);

        if (streq(key, "DEVTYPE")) {
                r = device_set_devtype(device, value);
                if (r < 0)
                        return r;
        } else if (streq(key, "IFINDEX")) {
                r = device_set_ifindex(device, value);
                if (r < 0)
                        return r;
        } else if (streq(key, "DEVNAME")) {
                r = device_set_devname(device, value);
                if (r < 0)
                        return r;
        } else if (streq(key, "DEVMODE")) {
                r = device_set_devmode(device, value);
                if (r < 0)
                        return r;
        } else if (streq(key, "MAJOR"))
                *major = value;
        else if (streq(key, "MINOR"))
                *minor = value;
        else {
                r = device_add_property_internal(device, key, value);
                if (r < 0)
                        return r;
        }

        return 0;
}

int device_read_uevent_file(sd_device *device) {
        _cleanup_free_ char *uevent = NULL;
        const char *syspath, *key = NULL, *value = NULL, *major = NULL, *minor = NULL;
        char *path;
        size_t uevent_len;
        unsigned i;
        int r;

        enum {
                PRE_KEY,
                KEY,
                PRE_VALUE,
                VALUE,
                INVALID_LINE,
        } state = PRE_KEY;

        assert(device);

        if (device->uevent_loaded || device->sealed)
                return 0;

        device->uevent_loaded = true;

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        path = strjoina(syspath, "/uevent");

        r = read_full_file(path, &uevent, &uevent_len);
        if (r == -EACCES)
                /* empty uevent files may be write-only */
                return 0;
        else if (r == -ENOENT)
                /* some devices may not have uevent files, see set_syspath() */
                return 0;
        else if (r < 0)
                return log_device_debug_errno(device, r, "sd-device: Failed to read uevent file '%s': %m", path);

        for (i = 0; i < uevent_len; i++)
                switch (state) {
                case PRE_KEY:
                        if (!strchr(NEWLINE, uevent[i])) {
                                key = &uevent[i];

                                state = KEY;
                        }

                        break;
                case KEY:
                        if (uevent[i] == '=') {
                                uevent[i] = '\0';

                                state = PRE_VALUE;
                        } else if (strchr(NEWLINE, uevent[i])) {
                                uevent[i] = '\0';
                                log_device_debug(device, "sd-device: Invalid uevent line '%s', ignoring", key);

                                state = PRE_KEY;
                        }

                        break;
                case PRE_VALUE:
                        value = &uevent[i];
                        state = VALUE;

                        _fallthrough_; /* to handle empty property */
                case VALUE:
                        if (strchr(NEWLINE, uevent[i])) {
                                uevent[i] = '\0';

                                r = handle_uevent_line(device, key, value, &major, &minor);
                                if (r < 0)
                                        log_device_debug_errno(device, r, "sd-device: Failed to handle uevent entry '%s=%s', ignoring: %m", key, value);

                                state = PRE_KEY;
                        }

                        break;
                default:
                        assert_not_reached("Invalid state when parsing uevent file");
                }

        if (major) {
                r = device_set_devnum(device, major, minor);
                if (r < 0)
                        log_device_debug_errno(device, r, "sd-device: Failed to set 'MAJOR=%s' or 'MINOR=%s' from '%s', ignoring: %m", major, minor, path);
        }

        return 0;
}

_public_ int sd_device_get_ifindex(sd_device *device, int *ifindex) {
        int r;

        assert_return(device, -EINVAL);

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

        if (device->ifindex <= 0)
                return -ENOENT;

        if (ifindex)
                *ifindex = device->ifindex;

        return 0;
}

_public_ int sd_device_new_from_device_id(sd_device **ret, const char *id) {
        int r;

        assert_return(ret, -EINVAL);
        assert_return(id, -EINVAL);

        switch (id[0]) {
        case 'b':
        case 'c':
        {
                char type;
                int maj, min;

                r = sscanf(id, "%c%i:%i", &type, &maj, &min);
                if (r != 3)
                        return -EINVAL;

                return sd_device_new_from_devnum(ret, type, makedev(maj, min));
        }
        case 'n':
        {
                _cleanup_(sd_device_unrefp) sd_device *device = NULL;
                _cleanup_close_ int sk = -1;
                struct ifreq ifr = {};
                int ifindex;

                r = parse_ifindex(&id[1], &ifr.ifr_ifindex);
                if (r < 0)
                        return r;

                sk = socket_ioctl_fd();
                if (sk < 0)
                        return sk;

                r = ioctl(sk, SIOCGIFNAME, &ifr);
                if (r < 0)
                        return -errno;

                r = sd_device_new_from_subsystem_sysname(&device, "net", ifr.ifr_name);
                if (r < 0)
                        return r;

                r = sd_device_get_ifindex(device, &ifindex);
                if (r < 0)
                        return r;

                /* this is racey, so we might end up with the wrong device */
                if (ifr.ifr_ifindex != ifindex)
                        return -ENODEV;

                *ret = TAKE_PTR(device);

                return 0;
        }
        case '+':
        {
                char subsys[PATH_MAX];
                char *sysname;

                (void) strscpy(subsys, sizeof(subsys), id + 1);
                sysname = strchr(subsys, ':');
                if (!sysname)
                        return -EINVAL;

                sysname[0] = '\0';
                sysname++;

                return sd_device_new_from_subsystem_sysname(ret, subsys, sysname);
        }
        default:
                return -EINVAL;
        }
}

_public_ int sd_device_get_syspath(sd_device *device, const char **ret) {
        assert_return(device, -EINVAL);
        assert_return(ret, -EINVAL);

        assert(path_startswith(device->syspath, "/sys/"));

        *ret = device->syspath;

        return 0;
}

static int device_new_from_child(sd_device **ret, sd_device *child) {
        _cleanup_free_ char *path = NULL;
        const char *subdir, *syspath;
        int r;

        assert(ret);
        assert(child);

        r = sd_device_get_syspath(child, &syspath);
        if (r < 0)
                return r;

        path = strdup(syspath);
        if (!path)
                return -ENOMEM;
        subdir = path + STRLEN("/sys");

        for (;;) {
                char *pos;

                pos = strrchr(subdir, '/');
                if (!pos || pos < subdir + 2)
                        break;

                *pos = '\0';

                r = sd_device_new_from_syspath(ret, path);
                if (r < 0)
                        continue;

                return 0;
        }

        return -ENODEV;
}

_public_ int sd_device_get_parent(sd_device *child, sd_device **ret) {

        assert_return(ret, -EINVAL);
        assert_return(child, -EINVAL);

        if (!child->parent_set) {
                child->parent_set = true;

                (void) device_new_from_child(&child->parent, child);
        }

        if (!child->parent)
                return -ENOENT;

        *ret = child->parent;

        return 0;
}

int device_set_subsystem(sd_device *device, const char *_subsystem) {
        _cleanup_free_ char *subsystem = NULL;
        int r;

        assert(device);
        assert(_subsystem);

        subsystem = strdup(_subsystem);
        if (!subsystem)
                return -ENOMEM;

        r = device_add_property_internal(device, "SUBSYSTEM", subsystem);
        if (r < 0)
                return r;

        free_and_replace(device->subsystem, subsystem);

        device->subsystem_set = true;

        return 0;
}

static int device_set_drivers_subsystem(sd_device *device, const char *_subsystem) {
        _cleanup_free_ char *subsystem = NULL;
        int r;

        assert(device);
        assert(_subsystem);
        assert(*_subsystem);

        subsystem = strdup(_subsystem);
        if (!subsystem)
                return -ENOMEM;

        r = device_set_subsystem(device, "drivers");
        if (r < 0)
                return r;

        free_and_replace(device->driver_subsystem, subsystem);

        return 0;
}

_public_ int sd_device_get_subsystem(sd_device *device, const char **ret) {
        const char *syspath, *drivers = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(device, -EINVAL);

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        if (!device->subsystem_set) {
                _cleanup_free_ char *subsystem = NULL;
                char *path;

                /* read 'subsystem' link */
                path = strjoina(syspath, "/subsystem");
                r = readlink_value(path, &subsystem);
                if (r >= 0)
                        r = device_set_subsystem(device, subsystem);
                /* use implicit names */
                else if (path_startswith(device->devpath, "/module/"))
                        r = device_set_subsystem(device, "module");
                else if (!(drivers = strstr(syspath, "/drivers/")) &&
                         (path_startswith(device->devpath, "/subsystem/") ||
                          path_startswith(device->devpath, "/class/") ||
                          path_startswith(device->devpath, "/bus/")))
                        r = device_set_subsystem(device, "subsystem");
                if (r < 0 && r != -ENOENT)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set subsystem for %s: %m", device->devpath);

                device->subsystem_set = true;
        } else if (!device->driver_subsystem_set)
                drivers = strstr(syspath, "/drivers/");

        if (!device->driver_subsystem_set) {
                if (drivers) {
                        _cleanup_free_ char *subpath = NULL;

                        subpath = strndup(syspath, drivers - syspath);
                        if (!subpath)
                                r = -ENOMEM;
                        else {
                                const char *subsys;

                                subsys = strrchr(subpath, '/');
                                if (!subsys)
                                        r = -EINVAL;
                                else
                                        r = device_set_drivers_subsystem(device, subsys + 1);
                        }
                        if (r < 0 && r != -ENOENT)
                                return log_device_debug_errno(device, r, "sd-device: Failed to set subsystem for driver %s: %m", device->devpath);
                }

                device->driver_subsystem_set = true;
        }

        if (!device->subsystem)
                return -ENOENT;

        *ret = device->subsystem;

        return 0;
}

_public_ int sd_device_get_devtype(sd_device *device, const char **devtype) {
        int r;

        assert(devtype);
        assert(device);

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

        if (!device->devtype)
                return -ENOENT;

        *devtype = device->devtype;

        return 0;
}

_public_ int sd_device_get_parent_with_subsystem_devtype(sd_device *child, const char *subsystem, const char *devtype, sd_device **ret) {
        sd_device *parent = NULL;
        int r;

        assert_return(child, -EINVAL);
        assert_return(subsystem, -EINVAL);

        r = sd_device_get_parent(child, &parent);
        while (r >= 0) {
                const char *parent_subsystem = NULL;
                const char *parent_devtype = NULL;

                (void) sd_device_get_subsystem(parent, &parent_subsystem);
                if (streq_ptr(parent_subsystem, subsystem)) {
                        if (!devtype)
                                break;

                        (void) sd_device_get_devtype(parent, &parent_devtype);
                        if (streq_ptr(parent_devtype, devtype))
                                break;
                }
                r = sd_device_get_parent(parent, &parent);
        }

        if (r < 0)
                return r;

        *ret = parent;

        return 0;
}

_public_ int sd_device_get_devnum(sd_device *device, dev_t *devnum) {
        int r;

        assert_return(device, -EINVAL);

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

        if (major(device->devnum) <= 0)
                return -ENOENT;

        if (devnum)
                *devnum = device->devnum;

        return 0;
}

int device_set_driver(sd_device *device, const char *_driver) {
        _cleanup_free_ char *driver = NULL;
        int r;

        assert(device);
        assert(_driver);

        driver = strdup(_driver);
        if (!driver)
                return -ENOMEM;

        r = device_add_property_internal(device, "DRIVER", driver);
        if (r < 0)
                return r;

        free_and_replace(device->driver, driver);

        device->driver_set = true;

        return 0;
}

_public_ int sd_device_get_driver(sd_device *device, const char **ret) {
        assert_return(device, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!device->driver_set) {
                _cleanup_free_ char *driver = NULL;
                const char *syspath;
                char *path;
                int r;

                r = sd_device_get_syspath(device, &syspath);
                if (r < 0)
                        return r;

                path = strjoina(syspath, "/driver");
                r = readlink_value(path, &driver);
                if (r >= 0) {
                        r = device_set_driver(device, driver);
                        if (r < 0)
                                return log_device_debug_errno(device, r, "sd-device: Failed to set driver for %s: %m", device->devpath);
                } else if (r == -ENOENT)
                        device->driver_set = true;
                else
                        return log_device_debug_errno(device, r, "sd-device: Failed to set driver for %s: %m", device->devpath);
        }

        if (!device->driver)
                return -ENOENT;

        *ret = device->driver;

        return 0;
}

_public_ int sd_device_get_devpath(sd_device *device, const char **devpath) {
        assert_return(device, -EINVAL);
        assert_return(devpath, -EINVAL);

        assert(device->devpath);
        assert(device->devpath[0] == '/');

        *devpath = device->devpath;

        return 0;
}

_public_ int sd_device_get_devname(sd_device *device, const char **devname) {
        int r;

        assert_return(device, -EINVAL);
        assert_return(devname, -EINVAL);

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

        if (!device->devname)
                return -ENOENT;

        assert(path_startswith(device->devname, "/dev/"));

        *devname = device->devname;

        return 0;
}

static int device_set_sysname(sd_device *device) {
        _cleanup_free_ char *sysname = NULL;
        const char *sysnum = NULL;
        const char *pos;
        size_t len = 0;

        pos = strrchr(device->devpath, '/');
        if (!pos)
                return -EINVAL;
        pos++;

        /* devpath is not a root directory */
        if (*pos == '\0' || pos <= device->devpath)
                return -EINVAL;

        sysname = strdup(pos);
        if (!sysname)
                return -ENOMEM;

        /* some devices have '!' in their name, change that to '/' */
        while (sysname[len] != '\0') {
                if (sysname[len] == '!')
                        sysname[len] = '/';

                len++;
        }

        /* trailing number */
        while (len > 0 && isdigit(sysname[--len]))
                sysnum = &sysname[len];

        if (len == 0)
                sysnum = NULL;

        free_and_replace(device->sysname, sysname);

        device->sysnum = sysnum;

        device->sysname_set = true;

        return 0;
}

_public_ int sd_device_get_sysname(sd_device *device, const char **ret) {
        int r;

        assert_return(device, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!device->sysname_set) {
                r = device_set_sysname(device);
                if (r < 0)
                        return r;
        }

        assert_return(device->sysname, -ENOENT);

        *ret = device->sysname;

        return 0;
}

_public_ int sd_device_get_sysnum(sd_device *device, const char **ret) {
        int r;

        assert_return(device, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!device->sysname_set) {
                r = device_set_sysname(device);
                if (r < 0)
                        return r;
        }

        if (!device->sysnum)
                return -ENOENT;

        *ret = device->sysnum;

        return 0;
}

static bool is_valid_tag(const char *tag) {
        assert(tag);

        return !strchr(tag, ':') && !strchr(tag, ' ');
}

int device_add_tag(sd_device *device, const char *tag) {
        int r;

        assert(device);
        assert(tag);

        if (!is_valid_tag(tag))
                return -EINVAL;

        r = set_ensure_allocated(&device->tags, &string_hash_ops);
        if (r < 0)
                return r;

        r = set_put_strdup(device->tags, tag);
        if (r < 0)
                return r;

        device->tags_generation++;
        device->property_tags_outdated = true;

        return 0;
}

int device_add_devlink(sd_device *device, const char *devlink) {
        int r;

        assert(device);
        assert(devlink);

        r = set_ensure_allocated(&device->devlinks, &string_hash_ops);
        if (r < 0)
                return r;

        r = set_put_strdup(device->devlinks, devlink);
        if (r < 0)
                return r;

        device->devlinks_generation++;
        device->property_devlinks_outdated = true;

        return 0;
}

static int device_add_property_internal_from_string(sd_device *device, const char *str) {
        _cleanup_free_ char *key = NULL;
        char *value;

        assert(device);
        assert(str);

        key = strdup(str);
        if (!key)
                return -ENOMEM;

        value = strchr(key, '=');
        if (!value)
                return -EINVAL;

        *value = '\0';

        if (isempty(++value))
                value = NULL;

        return device_add_property_internal(device, key, value);
}

int device_set_usec_initialized(sd_device *device, const char *initialized) {
        uint64_t usec_initialized;
        int r;

        assert(device);
        assert(initialized);

        r = safe_atou64(initialized, &usec_initialized);
        if (r < 0)
                return r;

        r = device_add_property_internal(device, "USEC_INITIALIZED", initialized);
        if (r < 0)
                return r;

        device->usec_initialized = usec_initialized;

        return 0;
}

static int handle_db_line(sd_device *device, char key, const char *value) {
        char *path;
        int r;

        assert(device);
        assert(value);

        switch (key) {
        case 'G':
                r = device_add_tag(device, value);
                if (r < 0)
                        return r;

                break;
        case 'S':
                path = strjoina("/dev/", value);
                r = device_add_devlink(device, path);
                if (r < 0)
                        return r;

                break;
        case 'E':
                r = device_add_property_internal_from_string(device, value);
                if (r < 0)
                        return r;

                break;
        case 'I':
                r = device_set_usec_initialized(device, value);
                if (r < 0)
                        return r;

                break;
        case 'L':
                r = safe_atoi(value, &device->devlink_priority);
                if (r < 0)
                        return r;

                break;
        case 'W':
                r = safe_atoi(value, &device->watch_handle);
                if (r < 0)
                        return r;

                break;
        default:
                log_device_debug(device, "sd-device: Unknown key '%c' in device db, ignoring", key);
        }

        return 0;
}

int device_get_id_filename(sd_device *device, const char **ret) {
        assert(device);
        assert(ret);

        if (!device->id_filename) {
                _cleanup_free_ char *id = NULL;
                const char *subsystem;
                dev_t devnum;
                int ifindex, r;

                r = sd_device_get_subsystem(device, &subsystem);
                if (r < 0)
                        return r;

                if (sd_device_get_devnum(device, &devnum) >= 0) {
                        assert(subsystem);

                        /* use dev_t — b259:131072, c254:0 */
                        r = asprintf(&id, "%c%u:%u",
                                     streq(subsystem, "block") ? 'b' : 'c',
                                     major(devnum), minor(devnum));
                        if (r < 0)
                                return -ENOMEM;
                } else if (sd_device_get_ifindex(device, &ifindex) >= 0) {
                        /* use netdev ifindex — n3 */
                        r = asprintf(&id, "n%u", (unsigned) ifindex);
                        if (r < 0)
                                return -ENOMEM;
                } else {
                        /* use $subsys:$sysname — pci:0000:00:1f.2
                         * sysname() has '!' translated, get it from devpath
                         */
                        const char *sysname;

                        sysname = basename(device->devpath);
                        if (!sysname)
                                return -EINVAL;

                        if (!subsystem)
                                return -EINVAL;

                        if (streq(subsystem, "drivers")) {
                                /* the 'drivers' pseudo-subsystem is special, and needs the real subsystem
                                 * encoded as well */
                                r = asprintf(&id, "+drivers:%s:%s", device->driver_subsystem, sysname);
                                if (r < 0)
                                        return -ENOMEM;
                        } else {
                                r = asprintf(&id, "+%s:%s", subsystem, sysname);
                                if (r < 0)
                                        return -ENOMEM;
                        }
                }

                device->id_filename = TAKE_PTR(id);
        }

        *ret = device->id_filename;

        return 0;
}

int device_read_db_aux(sd_device *device, bool force) {
        _cleanup_free_ char *db = NULL;
        char *path;
        const char *id, *value;
        char key;
        size_t db_len;
        unsigned i;
        int r;

        enum {
                PRE_KEY,
                KEY,
                PRE_VALUE,
                VALUE,
                INVALID_LINE,
        } state = PRE_KEY;

        if (device->db_loaded || (!force && device->sealed))
                return 0;

        device->db_loaded = true;

        r = device_get_id_filename(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/data/", id);

        r = read_full_file(path, &db, &db_len);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;
                else
                        return log_device_debug_errno(device, r, "sd-device: Failed to read db '%s': %m", path);
        }

        /* devices with a database entry are initialized */
        device->is_initialized = true;

        for (i = 0; i < db_len; i++) {
                switch (state) {
                case PRE_KEY:
                        if (!strchr(NEWLINE, db[i])) {
                                key = db[i];

                                state = KEY;
                        }

                        break;
                case KEY:
                        if (db[i] != ':') {
                                log_device_debug(device, "sd-device: Invalid db entry with key '%c', ignoring", key);

                                state = INVALID_LINE;
                        } else {
                                db[i] = '\0';

                                state = PRE_VALUE;
                        }

                        break;
                case PRE_VALUE:
                        value = &db[i];

                        state = VALUE;

                        break;
                case INVALID_LINE:
                        if (strchr(NEWLINE, db[i]))
                                state = PRE_KEY;

                        break;
                case VALUE:
                        if (strchr(NEWLINE, db[i])) {
                                db[i] = '\0';
                                r = handle_db_line(device, key, value);
                                if (r < 0)
                                        log_device_debug_errno(device, r, "sd-device: Failed to handle db entry '%c:%s', ignoring: %m", key, value);

                                state = PRE_KEY;
                        }

                        break;
                default:
                        assert_not_reached("Invalid state when parsing db");
                }
        }

        return 0;
}

static int device_read_db(sd_device *device) {
        return device_read_db_aux(device, false);
}

_public_ int sd_device_get_is_initialized(sd_device *device) {
        int r;

        assert_return(device, -EINVAL);

        r = device_read_db(device);
        if (r < 0)
                return r;

        return device->is_initialized;
}

_public_ int sd_device_get_usec_since_initialized(sd_device *device, uint64_t *usec) {
        usec_t now_ts;
        int r;

        assert_return(device, -EINVAL);
        assert_return(usec, -EINVAL);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (!device->is_initialized)
                return -EBUSY;

        if (!device->usec_initialized)
                return -ENODATA;

        now_ts = now(clock_boottime_or_monotonic());

        if (now_ts < device->usec_initialized)
                return -EIO;

        *usec = now_ts - device->usec_initialized;

        return 0;
}

_public_ const char *sd_device_get_tag_first(sd_device *device) {
        void *v;

        assert_return(device, NULL);

        (void) device_read_db(device);

        device->tags_iterator_generation = device->tags_generation;
        device->tags_iterator = ITERATOR_FIRST;

        (void) set_iterate(device->tags, &device->tags_iterator, &v);
        return v;
}

_public_ const char *sd_device_get_tag_next(sd_device *device) {
        void *v;

        assert_return(device, NULL);

        (void) device_read_db(device);

        if (device->tags_iterator_generation != device->tags_generation)
                return NULL;

        (void) set_iterate(device->tags, &device->tags_iterator, &v);
        return v;
}

_public_ const char *sd_device_get_devlink_first(sd_device *device) {
        void *v;

        assert_return(device, NULL);

        (void) device_read_db(device);

        device->devlinks_iterator_generation = device->devlinks_generation;
        device->devlinks_iterator = ITERATOR_FIRST;

        (void) set_iterate(device->devlinks, &device->devlinks_iterator, &v);
        return v;
}

_public_ const char *sd_device_get_devlink_next(sd_device *device) {
        void *v;

        assert_return(device, NULL);

        (void) device_read_db(device);

        if (device->devlinks_iterator_generation != device->devlinks_generation)
                return NULL;

        (void) set_iterate(device->devlinks, &device->devlinks_iterator, &v);
        return v;
}

static int device_properties_prepare(sd_device *device) {
        int r;

        assert(device);

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->property_devlinks_outdated) {
                _cleanup_free_ char *devlinks = NULL;
                size_t devlinks_allocated = 0, devlinks_len = 0;
                const char *devlink;

                for (devlink = sd_device_get_devlink_first(device); devlink; devlink = sd_device_get_devlink_next(device)) {
                        char *e;

                        if (!GREEDY_REALLOC(devlinks, devlinks_allocated, devlinks_len + strlen(devlink) + 2))
                                return -ENOMEM;
                        if (devlinks_len > 0)
                                stpcpy(devlinks + devlinks_len++, " ");
                        e = stpcpy(devlinks + devlinks_len, devlink);
                        devlinks_len = e - devlinks;
                }

                r = device_add_property_internal(device, "DEVLINKS", devlinks);
                if (r < 0)
                        return r;

                device->property_devlinks_outdated = false;
        }

        if (device->property_tags_outdated) {
                _cleanup_free_ char *tags = NULL;
                size_t tags_allocated = 0, tags_len = 0;
                const char *tag;

                if (!GREEDY_REALLOC(tags, tags_allocated, 2))
                        return -ENOMEM;
                stpcpy(tags, ":");
                tags_len++;

                for (tag = sd_device_get_tag_first(device); tag; tag = sd_device_get_tag_next(device)) {
                        char *e;

                        if (!GREEDY_REALLOC(tags, tags_allocated, tags_len + strlen(tag) + 2))
                                return -ENOMEM;
                        e = stpcpy(stpcpy(tags + tags_len, tag), ":");
                        tags_len = e - tags;
                }

                r = device_add_property_internal(device, "TAGS", tags);
                if (r < 0)
                        return r;

                device->property_tags_outdated = false;
        }

        return 0;
}

_public_ const char *sd_device_get_property_first(sd_device *device, const char **_value) {
        const char *key;
        const char *value;
        int r;

        assert_return(device, NULL);

        r = device_properties_prepare(device);
        if (r < 0)
                return NULL;

        device->properties_iterator_generation = device->properties_generation;
        device->properties_iterator = ITERATOR_FIRST;

        ordered_hashmap_iterate(device->properties, &device->properties_iterator, (void**)&value, (const void**)&key);

        if (_value)
                *_value = value;

        return key;
}

_public_ const char *sd_device_get_property_next(sd_device *device, const char **_value) {
        const char *key;
        const char *value;
        int r;

        assert_return(device, NULL);

        r = device_properties_prepare(device);
        if (r < 0)
                return NULL;

        if (device->properties_iterator_generation != device->properties_generation)
                return NULL;

        ordered_hashmap_iterate(device->properties, &device->properties_iterator, (void**)&value, (const void**)&key);

        if (_value)
                *_value = value;

        return key;
}

static int device_sysattrs_read_all(sd_device *device) {
        _cleanup_closedir_ DIR *dir = NULL;
        const char *syspath;
        struct dirent *dent;
        int r;

        assert(device);

        if (device->sysattrs_read)
                return 0;

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        dir = opendir(syspath);
        if (!dir)
                return -errno;

        r = set_ensure_allocated(&device->sysattrs, &string_hash_ops);
        if (r < 0)
                return r;

        FOREACH_DIRENT_ALL(dent, dir, return -errno) {
                char *path;
                struct stat statbuf;

                /* only handle symlinks and regular files */
                if (!IN_SET(dent->d_type, DT_LNK, DT_REG))
                        continue;

                path = strjoina(syspath, "/", dent->d_name);

                if (lstat(path, &statbuf) != 0)
                        continue;

                if (!(statbuf.st_mode & S_IRUSR))
                        continue;

                r = set_put_strdup(device->sysattrs, dent->d_name);
                if (r < 0)
                        return r;
        }

        device->sysattrs_read = true;

        return 0;
}

_public_ const char *sd_device_get_sysattr_first(sd_device *device) {
        void *v;
        int r;

        assert_return(device, NULL);

        if (!device->sysattrs_read) {
                r = device_sysattrs_read_all(device);
                if (r < 0) {
                        errno = -r;
                        return NULL;
                }
        }

        device->sysattrs_iterator = ITERATOR_FIRST;

        (void) set_iterate(device->sysattrs, &device->sysattrs_iterator, &v);
        return v;
}

_public_ const char *sd_device_get_sysattr_next(sd_device *device) {
        void *v;

        assert_return(device, NULL);

        if (!device->sysattrs_read)
                return NULL;

        (void) set_iterate(device->sysattrs, &device->sysattrs_iterator, &v);
        return v;
}

_public_ int sd_device_has_tag(sd_device *device, const char *tag) {
        assert_return(device, -EINVAL);
        assert_return(tag, -EINVAL);

        (void) device_read_db(device);

        return !!set_contains(device->tags, tag);
}

_public_ int sd_device_get_property_value(sd_device *device, const char *key, const char **_value) {
        char *value;
        int r;

        assert_return(device, -EINVAL);
        assert_return(key, -EINVAL);

        r = device_properties_prepare(device);
        if (r < 0)
                return r;

        value = ordered_hashmap_get(device->properties, key);
        if (!value)
                return -ENOENT;

        if (_value)
                *_value = value;

        return 0;
}

/* replaces the value if it already exists */
static int device_add_sysattr_value(sd_device *device, const char *_key, char *value) {
        _cleanup_free_ char *key = NULL;
        _cleanup_free_ char *value_old = NULL;
        int r;

        assert(device);
        assert(_key);

        r = hashmap_ensure_allocated(&device->sysattr_values, &string_hash_ops);
        if (r < 0)
                return r;

        value_old = hashmap_remove2(device->sysattr_values, _key, (void **)&key);
        if (!key) {
                key = strdup(_key);
                if (!key)
                        return -ENOMEM;
        }

        r = hashmap_put(device->sysattr_values, key, value);
        if (r < 0)
                return r;

        key = NULL;

        return 0;
}

static int device_get_sysattr_value(sd_device *device, const char *_key, const char **_value) {
        const char *key = NULL, *value;

        assert(device);
        assert(_key);

        value = hashmap_get2(device->sysattr_values, _key, (void **) &key);
        if (!key)
                return -ENOENT;

        if (_value)
                *_value = value;

        return 0;
}

/* We cache all sysattr lookups. If an attribute does not exist, it is stored
 * with a NULL value in the cache, otherwise the returned string is stored */
_public_ int sd_device_get_sysattr_value(sd_device *device, const char *sysattr, const char **_value) {
        _cleanup_free_ char *value = NULL;
        const char *syspath, *cached_value = NULL;
        char *path;
        struct stat statbuf;
        int r;

        assert_return(device, -EINVAL);
        assert_return(sysattr, -EINVAL);

        /* look for possibly already cached result */
        r = device_get_sysattr_value(device, sysattr, &cached_value);
        if (r != -ENOENT) {
                if (r < 0)
                        return r;

                if (!cached_value)
                        /* we looked up the sysattr before and it did not exist */
                        return -ENOENT;

                if (_value)
                        *_value = cached_value;

                return 0;
        }

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        path = strjoina(syspath, "/", sysattr);
        r = lstat(path, &statbuf);
        if (r < 0) {
                /* remember that we could not access the sysattr */
                r = device_add_sysattr_value(device, sysattr, NULL);
                if (r < 0)
                        return r;

                return -ENOENT;
        } else if (S_ISLNK(statbuf.st_mode)) {
                /* Some core links return only the last element of the target path,
                 * these are just values, the paths should not be exposed. */
                if (STR_IN_SET(sysattr, "driver", "subsystem", "module")) {
                        r = readlink_value(path, &value);
                        if (r < 0)
                                return r;
                } else
                        return -EINVAL;
        } else if (S_ISDIR(statbuf.st_mode)) {
                /* skip directories */
                return -EINVAL;
        } else if (!(statbuf.st_mode & S_IRUSR)) {
                /* skip non-readable files */
                return -EPERM;
        } else {
                size_t size;

                /* read attribute value */
                r = read_full_file(path, &value, &size);
                if (r < 0)
                        return r;

                /* drop trailing newlines */
                while (size > 0 && value[--size] == '\n')
                        value[size] = '\0';
        }

        r = device_add_sysattr_value(device, sysattr, value);
        if (r < 0)
                return r;

        *_value = TAKE_PTR(value);

        return 0;
}

static void device_remove_sysattr_value(sd_device *device, const char *_key) {
        _cleanup_free_ char *key = NULL;
        _cleanup_free_ char *value = NULL;

        assert(device);
        assert(_key);

        value = hashmap_remove2(device->sysattr_values, _key, (void **) &key);

        return;
}

/* set the attribute and save it in the cache. If a NULL value is passed the
 * attribute is cleared from the cache */
_public_ int sd_device_set_sysattr_value(sd_device *device, const char *sysattr, const char *_value) {
        _cleanup_free_ char *value = NULL;
        const char *syspath, *path;
        size_t len;
        int r;

        assert_return(device, -EINVAL);
        assert_return(sysattr, -EINVAL);

        if (!_value) {
                device_remove_sysattr_value(device, sysattr);

                return 0;
        }

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        path = strjoina(syspath, "/", sysattr);

        len = strlen(_value);

        /* drop trailing newlines */
        while (len > 0 && _value[len - 1] == '\n')
                len --;

        /* value length is limited to 4k */
        if (len > 4096)
                return -EINVAL;

        value = strndup(_value, len);
        if (!value)
                return -ENOMEM;

        r = write_string_file(path, value, WRITE_STRING_FILE_DISABLE_BUFFER | WRITE_STRING_FILE_NOFOLLOW);
        if (r < 0) {
                if (r == -ELOOP)
                        return -EINVAL;
                if (r == -EISDIR)
                        return r;

                free(value);
                value = strdup("");
                if (!value)
                        return -ENOMEM;

                r = device_add_sysattr_value(device, sysattr, value);
                if (r < 0)
                        return r;

                value = NULL;
                return -ENXIO;
        }

        r = device_add_sysattr_value(device, sysattr, value);
        if (r < 0)
                return r;

        value = NULL;
        return 0;
}
