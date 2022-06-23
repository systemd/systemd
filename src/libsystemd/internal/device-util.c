/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <fnmatch.h>
#include <linux/magic.h>
#include <net/if.h>
#include <sys/types.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "device-util.h"
#include "devnum-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "macro.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "set.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "tmpfile-util.h"
#include "user-util.h"

int device_add_property(sd_device *device, const char *key, const char *value) {
        int r;

        assert(device);
        assert(key);

        r = device_add_property_aux(device, key, value, false);
        if (r < 0)
                return r;

        if (key[0] != '.') {
                r = device_add_property_aux(device, key, value, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

int device_add_propertyf(sd_device *device, const char *key, const char *format, ...) {
        _cleanup_free_ char *value = NULL;
        va_list ap;
        int r;

        assert(device);
        assert(key);

        if (!format)
                return device_add_property(device, key, NULL);

        va_start(ap, format);
        r = vasprintf(&value, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return device_add_property(device, key, value);
}

void device_set_devlink_priority(sd_device *device, int priority) {
        assert(device);

        device->devlink_priority = priority;
}

void device_set_is_initialized(sd_device *device) {
        assert(device);

        device->is_initialized = true;
}

int device_ensure_usec_initialized(sd_device *device, sd_device *device_old) {
        usec_t when;

        assert(device);

        if (device_old && device_old->usec_initialized > 0)
                when = device_old->usec_initialized;
        else
                when = now(CLOCK_MONOTONIC);

        return device_set_usec_initialized(device, when);
}

uint64_t device_get_properties_generation(sd_device *device) {
        assert(device);

        return device->properties_generation;
}

uint64_t device_get_tags_generation(sd_device *device) {
        assert(device);

        return device->tags_generation;
}

uint64_t device_get_devlinks_generation(sd_device *device) {
        assert(device);

        return device->devlinks_generation;
}

static int device_set_devuid(sd_device *device, const char *uid) {
        uid_t u;
        int r;

        assert(device);
        assert(uid);

        r = parse_uid(uid, &u);
        if (r < 0)
                return r;

        r = device_add_property_internal(device, "DEVUID", uid);
        if (r < 0)
                return r;

        device->devuid = u;

        return 0;
}

static int device_set_devgid(sd_device *device, const char *gid) {
        gid_t g;
        int r;

        assert(device);
        assert(gid);

        r = parse_gid(gid, &g);
        if (r < 0)
                return r;

        r = device_add_property_internal(device, "DEVGID", gid);
        if (r < 0)
                return r;

        device->devgid = g;

        return 0;
}

static int device_set_action_from_string(sd_device *device, const char *action) {
        sd_device_action_t a;

        assert(device);
        assert(action);

        a = device_action_from_string(action);
        if (a < 0)
                return a;

        return device_set_action(device, a);
}

static int device_set_seqnum(sd_device *device, const char *str) {
        uint64_t seqnum;
        int r;

        assert(device);
        assert(str);

        r = safe_atou64(str, &seqnum);
        if (r < 0)
                return r;
        if (seqnum == 0)
                return -EINVAL;

        r = device_add_property_internal(device, "SEQNUM", str);
        if (r < 0)
                return r;

        device->seqnum = seqnum;

        return 0;
}

static int device_amend(sd_device *device, const char *key, const char *value) {
        int r;

        assert(device);
        assert(key);
        assert(value);

        if (streq(key, "DEVPATH")) {
                char *path;

                path = strjoina("/sys", value);

                /* the caller must verify or trust this data (e.g., if it comes from the kernel) */
                r = device_set_syspath(device, path, false);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set syspath to '%s': %m", path);
        } else if (streq(key, "SUBSYSTEM")) {
                r = device_set_subsystem(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set subsystem to '%s': %m", value);
        } else if (streq(key, "DEVTYPE")) {
                r = device_set_devtype(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devtype to '%s': %m", value);
        } else if (streq(key, "DEVNAME")) {
                r = device_set_devname(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devname to '%s': %m", value);
        } else if (streq(key, "USEC_INITIALIZED")) {
                usec_t t;

                r = safe_atou64(value, &t);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to parse timestamp '%s': %m", value);

                r = device_set_usec_initialized(device, t);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set usec-initialized to '%s': %m", value);
        } else if (streq(key, "DRIVER")) {
                r = device_set_driver(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set driver to '%s': %m", value);
        } else if (streq(key, "IFINDEX")) {
                r = device_set_ifindex(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set ifindex to '%s': %m", value);
        } else if (streq(key, "DEVMODE")) {
                r = device_set_devmode(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devmode to '%s': %m", value);
        } else if (streq(key, "DEVUID")) {
                r = device_set_devuid(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devuid to '%s': %m", value);
        } else if (streq(key, "DEVGID")) {
                r = device_set_devgid(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devgid to '%s': %m", value);
        } else if (streq(key, "ACTION")) {
                r = device_set_action_from_string(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set action to '%s': %m", value);
        } else if (streq(key, "SEQNUM")) {
                r = device_set_seqnum(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set SEQNUM to '%s': %m", value);
        } else if (streq(key, "DISKSEQ")) {
                r = device_set_diskseq(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set DISKSEQ to '%s': %m", value);
        } else if (streq(key, "DEVLINKS")) {
                for (const char *p = value;;) {
                        _cleanup_free_ char *word = NULL;

                        /* udev rules may set escaped strings, and sd-device does not modify the input
                         * strings. So, it is also necessary to keep the strings received through
                         * sd-device-monitor. */
                        r = extract_first_word(&p, &word, NULL, EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = device_add_devlink(device, word);
                        if (r < 0)
                                return log_device_debug_errno(device, r, "sd-device: Failed to add devlink '%s': %m", word);
                }
        } else if (STR_IN_SET(key, "TAGS", "CURRENT_TAGS")) {
                for (const char *p = value;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = device_add_tag(device, word, streq(key, "CURRENT_TAGS"));
                        if (r < 0)
                                return log_device_debug_errno(device, r, "sd-device: Failed to add tag '%s': %m", word);
                }
        } else {
                r = device_add_property_internal(device, key, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to add property '%s=%s': %m", key, value);
        }

        return 0;
}

static int device_append(
                sd_device *device,
                char *key,
                const char **_major,
                const char **_minor) {

        const char *major = NULL, *minor = NULL;
        char *value;
        int r;

        assert(device);
        assert(key);
        assert(_major);
        assert(_minor);

        value = strchr(key, '=');
        if (!value)
                return log_device_debug_errno(device, SYNTHETIC_ERRNO(EINVAL),
                                              "sd-device: Not a key-value pair: '%s'", key);

        *value = '\0';

        value++;

        if (streq(key, "MAJOR"))
                major = value;
        else if (streq(key, "MINOR"))
                minor = value;
        else {
                r = device_amend(device, key, value);
                if (r < 0)
                        return r;
        }

        if (major)
                *_major = major;

        if (minor)
                *_minor = minor;

        return 0;
}

int device_cache_sysattr_value(sd_device *device, const char *key, char *value) {
        _unused_ _cleanup_free_ char *old_value = NULL;
        _cleanup_free_ char *new_key = NULL;
        int r;

        assert(device);
        assert(key);

        /* This takes the reference of the input value. The input value may be NULL.
         * This replaces the value if it already exists. */

        /* First, remove the old cache entry. So, we do not need to clear cache on error. */
        old_value = hashmap_remove2(device->sysattr_values, key, (void **) &new_key);
        if (!new_key) {
                new_key = strdup(key);
                if (!new_key)
                        return -ENOMEM;
        }

        r = hashmap_ensure_put(&device->sysattr_values, &string_hash_ops_free_free, new_key, value);
        if (r < 0)
                return r;

        TAKE_PTR(new_key);

        return 0;
}

int device_get_cached_sysattr_value(sd_device *device, const char *key, const char **ret_value) {
        const char *k = NULL, *value;

        assert(device);
        assert(key);

        value = hashmap_get2(device->sysattr_values, key, (void **) &k);
        if (!k)
                return -ESTALE; /* We have not read the attribute. */
        if (!value)
                return -ENOENT; /* We have looked up the attribute before and it did not exist. */
        if (ret_value)
                *ret_value = value;
        return 0;
}

void device_seal(sd_device *device) {
        assert(device);

        device->sealed = true;
}

static int device_verify(sd_device *device) {
        int r;

        assert(device);

        if (!device->devpath || !device->subsystem || device->action < 0 || device->seqnum == 0)
                return log_device_debug_errno(device, SYNTHETIC_ERRNO(EINVAL),
                                              "sd-device: Device created from strv or nulstr lacks devpath, subsystem, action or seqnum.");

        if (streq(device->subsystem, "drivers")) {
                r = device_set_drivers_subsystem(device);
                if (r < 0)
                        return r;
        }

        device->sealed = true;

        return 0;
}

int device_new_from_nulstr(sd_device **ret, uint8_t *nulstr, size_t len) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *major = NULL, *minor = NULL;
        int r;

        assert(ret);
        assert(nulstr);
        assert(len);

        r = device_new_aux(&device);
        if (r < 0)
                return r;

        for (size_t i = 0; i < len; ) {
                char *key;
                const char *end;

                key = (char*) &nulstr[i];
                end = memchr(key, '\0', len - i);
                if (!end)
                        return log_device_debug_errno(device, SYNTHETIC_ERRNO(EINVAL),
                                                      "sd-device: Failed to parse nulstr");

                i += end - key + 1;

                /* netlink messages for some devices contain an unwanted newline at the end of value.
                 * Let's drop the newline and remaining characters after the newline. */
                truncate_nl(key);

                r = device_append(device, key, &major, &minor);
                if (r < 0)
                        return r;
        }

        if (major) {
                r = device_set_devnum(device, major, minor);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devnum %s:%s: %m", major, minor);
        }

        r = device_verify(device);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(device);

        return 0;
}

static int device_update_properties_bufs(sd_device *device) {
        const char *val, *prop;
        _cleanup_free_ char **buf_strv = NULL;
        _cleanup_free_ uint8_t *buf_nulstr = NULL;
        size_t nulstr_len = 0, num = 0, i = 0;

        assert(device);

        if (!device->properties_buf_outdated)
                return 0;

        FOREACH_DEVICE_PROPERTY(device, prop, val) {
                size_t len = 0;

                len = strlen(prop) + 1 + strlen(val);

                buf_nulstr = GREEDY_REALLOC0(buf_nulstr, nulstr_len + len + 2);
                if (!buf_nulstr)
                        return -ENOMEM;

                strscpyl((char *)buf_nulstr + nulstr_len, len + 1, prop, "=", val, NULL);
                nulstr_len += len + 1;
                ++num;
        }

        /* build buf_strv from buf_nulstr */
        buf_strv = new0(char *, num + 1);
        if (!buf_strv)
                return -ENOMEM;

        NULSTR_FOREACH(val, (char*) buf_nulstr) {
                buf_strv[i] = (char *) val;
                assert(i < num);
                i++;
        }

        free_and_replace(device->properties_nulstr, buf_nulstr);
        device->properties_nulstr_len = nulstr_len;
        free_and_replace(device->properties_strv, buf_strv);

        device->properties_buf_outdated = false;

        return 0;
}

int device_properties_prepare(sd_device *device) {
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

                r = set_strjoin(device->devlinks, " ", false, &devlinks);
                if (r < 0)
                        return r;

                if (!isempty(devlinks)) {
                        r = device_add_property_internal(device, "DEVLINKS", devlinks);
                        if (r < 0)
                                return r;
                }

                device->property_devlinks_outdated = false;
        }

        if (device->property_tags_outdated) {
                _cleanup_free_ char *tags = NULL;

                r = set_strjoin(device->all_tags, ":", true, &tags);
                if (r < 0)
                        return r;

                if (!isempty(tags)) {
                        r = device_add_property_internal(device, "TAGS", tags);
                        if (r < 0)
                                return r;
                }

                tags = mfree(tags);
                r = set_strjoin(device->current_tags, ":", true, &tags);
                if (r < 0)
                        return r;

                if (!isempty(tags)) {
                        r = device_add_property_internal(device, "CURRENT_TAGS", tags);
                        if (r < 0)
                                return r;
                }

                device->property_tags_outdated = false;
        }

        return 0;
}

int device_get_properties_nulstr(sd_device *device, const uint8_t **nulstr, size_t *len) {
        int r;

        assert(device);
        assert(nulstr);
        assert(len);

        r = device_update_properties_bufs(device);
        if (r < 0)
                return r;

        *nulstr = device->properties_nulstr;
        *len = device->properties_nulstr_len;

        return 0;
}

int device_get_properties_strv(sd_device *device, char ***strv) {
        int r;

        assert(device);
        assert(strv);

        r = device_update_properties_bufs(device);
        if (r < 0)
                return r;

        *strv = device->properties_strv;

        return 0;
}

int device_get_devlink_priority(sd_device *device, int *ret) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (ret)
                *ret = device->devlink_priority;

        return 0;
}

int device_get_watch_handle(sd_device *device) {
        char path_wd[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *buf = NULL;
        const char *id, *path_id;
        int wd, r;

        assert(device);

        if (device->watch_handle >= 0)
                return device->watch_handle;

        r = device_get_device_id(device, &id);
        if (r < 0)
                return r;

        path_id = strjoina("/run/udev/watch/", id);
        r = readlink_malloc(path_id, &buf);
        if (r < 0)
                return r;

        r = safe_atoi(buf, &wd);
        if (r < 0)
                return r;

        if (wd < 0)
                return -EBADF;

        buf = mfree(buf);
        xsprintf(path_wd, "/run/udev/watch/%d", wd);
        r = readlink_malloc(path_wd, &buf);
        if (r < 0)
                return r;

        if (!streq(buf, id))
                return -EBADF;

        return device->watch_handle = wd;
}

static void device_remove_watch_handle(sd_device *device) {
        const char *id;
        int wd;

        assert(device);

        /* First, remove the symlink from handle to device id. */
        wd = device_get_watch_handle(device);
        if (wd >= 0) {
                char path_wd[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];

                xsprintf(path_wd, "/run/udev/watch/%d", wd);
                if (unlink(path_wd) < 0 && errno != ENOENT)
                        log_device_debug_errno(device, errno,
                                               "sd-device: failed to remove %s, ignoring: %m",
                                               path_wd);
        }

        /* Next, remove the symlink from device id to handle. */
        if (device_get_device_id(device, &id) >= 0) {
                const char *path_id;

                path_id = strjoina("/run/udev/watch/", id);
                if (unlink(path_id) < 0 && errno != ENOENT)
                        log_device_debug_errno(device, errno,
                                               "sd-device: failed to remove %s, ignoring: %m",
                                               path_id);
        }

        device->watch_handle = -1;
}

int device_set_watch_handle(sd_device *device, int wd) {
        char path_wd[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        const char *id, *path_id;
        int r;

        assert(device);

        if (wd >= 0 && wd == device_get_watch_handle(device))
                return 0;

        device_remove_watch_handle(device);

        if (wd < 0)
                /* negative wd means that the caller requests to clear saved watch handle. */
                return 0;

        r = device_get_device_id(device, &id);
        if (r < 0)
                return r;

        path_id = strjoina("/run/udev/watch/", id);
        xsprintf(path_wd, "/run/udev/watch/%d", wd);

        r = mkdir_parents(path_wd, 0755);
        if (r < 0)
                return r;

        if (symlink(id, path_wd) < 0)
                return -errno;

        if (symlink(path_wd + STRLEN("/run/udev/watch/"), path_id) < 0) {
                r = -errno;
                if (unlink(path_wd) < 0 && errno != ENOENT)
                        log_device_debug_errno(device, errno,
                                               "sd-device: failed to remove %s, ignoring: %m",
                                               path_wd);
                return r;
        }

        device->watch_handle = wd;

        return 0;
}

int device_new_from_watch_handle_at(sd_device **ret, int dirfd, int wd) {
        char path_wd[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *id = NULL;
        int r;

        assert(ret);

        if (wd < 0)
                return -EBADF;

        if (dirfd >= 0) {
                xsprintf(path_wd, "%d", wd);
                r = readlinkat_malloc(dirfd, path_wd, &id);
        } else {
                xsprintf(path_wd, "/run/udev/watch/%d", wd);
                r = readlink_malloc(path_wd, &id);
        }
        if (r < 0)
                return r;

        return sd_device_new_from_device_id(ret, id);
}

int device_rename(sd_device *device, const char *name) {
        _cleanup_free_ char *new_syspath = NULL;
        const char *interface;
        int r;

        assert(device);
        assert(name);

        if (!filename_is_valid(name))
                return -EINVAL;

        r = path_extract_directory(device->syspath, &new_syspath);
        if (r < 0)
                return r;

        if (!path_extend(&new_syspath, name))
                return -ENOMEM;

        if (!path_is_safe(new_syspath))
                return -EINVAL;

        /* At the time this is called, the renamed device may not exist yet. Hence, we cannot validate
         * the new syspath. */
        r = device_set_syspath(device, new_syspath, false);
        if (r < 0)
                return r;

        /* Here, only clear the sysname and sysnum. They will be set when requested. */
        device->sysnum = NULL;
        device->sysname = mfree(device->sysname);

        r = sd_device_get_property_value(device, "INTERFACE", &interface);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        /* like DEVPATH_OLD, INTERFACE_OLD is not saved to the db, but only stays around for the current event */
        r = device_add_property_internal(device, "INTERFACE_OLD", interface);
        if (r < 0)
                return r;

        return device_add_property_internal(device, "INTERFACE", name);
}

int device_shallow_clone(sd_device *device, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dest = NULL;
        const char *val = NULL;
        int r;

        assert(device);
        assert(ret);

        r = device_new_aux(&dest);
        if (r < 0)
                return r;

        r = device_set_syspath(dest, device->syspath, false);
        if (r < 0)
                return r;

        (void) sd_device_get_subsystem(device, &val);
        r = device_set_subsystem(dest, val);
        if (r < 0)
                return r;
        if (streq_ptr(val, "drivers")) {
                r = free_and_strdup(&dest->driver_subsystem, device->driver_subsystem);
                if (r < 0)
                        return r;
        }

        /* The device may be already removed. Let's copy minimal set of information to make
         * device_get_device_id() work without uevent file. */

        if (sd_device_get_property_value(device, "IFINDEX", &val) >= 0) {
                r = device_set_ifindex(dest, val);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_property_value(device, "MAJOR", &val) >= 0) {
                const char *minor = NULL;

                (void) sd_device_get_property_value(device, "MINOR", &minor);
                r = device_set_devnum(dest, val, minor);
                if (r < 0)
                        return r;
        }

        r = device_read_uevent_file(dest);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dest);
        return 0;
}

int device_clone_with_db(sd_device *device, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dest = NULL;
        int r;

        assert(device);
        assert(ret);

        r = device_shallow_clone(device, &dest);
        if (r < 0)
                return r;

        r = device_read_db(dest);
        if (r < 0)
                return r;

        dest->sealed = true;

        *ret = TAKE_PTR(dest);
        return 0;
}

int device_copy_properties(sd_device *device_dst, sd_device *device_src) {
        const char *property, *value;
        int r;

        assert(device_dst);
        assert(device_src);

        r = device_properties_prepare(device_src);
        if (r < 0)
                return r;

        ORDERED_HASHMAP_FOREACH_KEY(value, property, device_src->properties_db) {
                r = device_add_property_aux(device_dst, property, value, true);
                if (r < 0)
                        return r;
        }

        ORDERED_HASHMAP_FOREACH_KEY(value, property, device_src->properties) {
                r = device_add_property_aux(device_dst, property, value, false);
                if (r < 0)
                        return r;
        }

        return 0;
}

void device_cleanup_tags(sd_device *device) {
        assert(device);

        device->all_tags = set_free_free(device->all_tags);
        device->current_tags = set_free_free(device->current_tags);
        device->property_tags_outdated = true;
        device->tags_generation++;
}

void device_cleanup_devlinks(sd_device *device) {
        assert(device);

        set_free_free(device->devlinks);
        device->devlinks = NULL;
        device->property_devlinks_outdated = true;
        device->devlinks_generation++;
}

void device_remove_tag(sd_device *device, const char *tag) {
        assert(device);
        assert(tag);

        free(set_remove(device->current_tags, tag));
        device->property_tags_outdated = true;
        device->tags_generation++;
}

static int device_tag(sd_device *device, const char *tag, bool add) {
        const char *id;
        char *path;
        int r;

        assert(device);
        assert(tag);

        r = device_get_device_id(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/tags/", tag, "/", id);

        if (add)
                return touch_file(path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0444);

        if (unlink(path) < 0 && errno != ENOENT)
                return -errno;

        return 0;
}

int device_tag_index(sd_device *device, sd_device *device_old, bool add) {
        const char *tag;
        int r = 0, k;

        if (add && device_old)
                /* delete possible left-over tags */
                FOREACH_DEVICE_TAG(device_old, tag)
                        if (!sd_device_has_tag(device, tag)) {
                                k = device_tag(device_old, tag, false);
                                if (r >= 0 && k < 0)
                                        r = k;
                        }

        FOREACH_DEVICE_TAG(device, tag) {
                k = device_tag(device, tag, add);
                if (r >= 0 && k < 0)
                        r = k;
        }

        return r;
}

static bool device_has_info(sd_device *device) {
        assert(device);

        if (!set_isempty(device->devlinks))
                return true;

        if (device->devlink_priority != 0)
                return true;

        if (!ordered_hashmap_isempty(device->properties_db))
                return true;

        if (!set_isempty(device->all_tags))
                return true;

        if (!set_isempty(device->current_tags))
                return true;

        return false;
}

void device_set_db_persist(sd_device *device) {
        assert(device);

        device->db_persist = true;
}

int device_update_db(sd_device *device) {
        const char *id;
        char *path;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *path_tmp = NULL;
        bool has_info;
        int r;

        assert(device);

        has_info = device_has_info(device);

        r = device_get_device_id(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/data/", id);

        /* do not store anything for otherwise empty devices */
        if (!has_info && major(device->devnum) == 0 && device->ifindex == 0) {
                if (unlink(path) < 0 && errno != ENOENT)
                        return -errno;

                return 0;
        }

        /* write a database file */
        r = mkdir_parents(path, 0755);
        if (r < 0)
                return r;

        r = fopen_temporary(path, &f, &path_tmp);
        if (r < 0)
                return r;

        /*
         * set 'sticky' bit to indicate that we should not clean the
         * database when we transition from initramfs to the real root
         */
        if (fchmod(fileno(f), device->db_persist ? 01644 : 0644) < 0) {
                r = -errno;
                goto fail;
        }

        if (has_info) {
                const char *property, *value, *tag;

                if (major(device->devnum) > 0) {
                        const char *devlink;

                        FOREACH_DEVICE_DEVLINK(device, devlink)
                                fprintf(f, "S:%s\n", devlink + STRLEN("/dev/"));

                        if (device->devlink_priority != 0)
                                fprintf(f, "L:%i\n", device->devlink_priority);
                }

                if (device->usec_initialized > 0)
                        fprintf(f, "I:"USEC_FMT"\n", device->usec_initialized);

                ORDERED_HASHMAP_FOREACH_KEY(value, property, device->properties_db)
                        fprintf(f, "E:%s=%s\n", property, value);

                FOREACH_DEVICE_TAG(device, tag)
                        fprintf(f, "G:%s\n", tag); /* Any tag */

                SET_FOREACH(tag, device->current_tags)
                        fprintf(f, "Q:%s\n", tag); /* Current tag */

                /* Always write the latest database version here, instead of the value stored in
                 * device->database_version, as which may be 0. */
                fputs("V:" STRINGIFY(LATEST_UDEV_DATABASE_VERSION) "\n", f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(path_tmp, path) < 0) {
                r = -errno;
                goto fail;
        }

        log_device_debug(device, "sd-device: Created %s file '%s' for '%s'", has_info ? "db" : "empty",
                         path, device->devpath);

        return 0;

fail:
        (void) unlink(path);
        (void) unlink(path_tmp);

        return log_device_debug_errno(device, r, "sd-device: Failed to create %s file '%s' for '%s'", has_info ? "db" : "empty", path, device->devpath);
}

int device_delete_db(sd_device *device) {
        const char *id;
        char *path;
        int r;

        assert(device);

        r = device_get_device_id(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/data/", id);

        if (unlink(path) < 0 && errno != ENOENT)
                return -errno;

        return 0;
}

int device_new_from_strv(sd_device **ret, char **strv) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *major = NULL, *minor = NULL;
        int r;

        assert(ret);
        assert(strv);

        r = device_new_aux(&device);
        if (r < 0)
                return r;

        STRV_FOREACH(key, strv) {
                r = device_append(device, *key, &major, &minor);
                if (r < 0)
                        return r;
        }

        if (major) {
                r = device_set_devnum(device, major, minor);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devnum %s:%s: %m", major, minor);
        }

        r = device_verify(device);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(device);

        return 0;
}

int device_new_aux(sd_device **ret) {
        sd_device *device;

        assert(ret);

        device = new(sd_device, 1);
        if (!device)
                return -ENOMEM;

        *device = (sd_device) {
                .n_ref = 1,
                .watch_handle = -1,
                .devmode = MODE_INVALID,
                .devuid = UID_INVALID,
                .devgid = GID_INVALID,
                .action = _SD_DEVICE_ACTION_INVALID,
        };

        *ret = device;
        return 0;
}

int device_add_property_aux(sd_device *device, const char *key, const char *value, bool db) {
        OrderedHashmap **properties;

        assert(device);
        assert(key);

        if (db)
                properties = &device->properties_db;
        else
                properties = &device->properties;

        if (value) {
                _unused_ _cleanup_free_ char *old_value = NULL;
                _cleanup_free_ char *new_key = NULL, *new_value = NULL, *old_key = NULL;
                int r;

                r = ordered_hashmap_ensure_allocated(properties, &string_hash_ops_free_free);
                if (r < 0)
                        return r;

                new_key = strdup(key);
                if (!new_key)
                        return -ENOMEM;

                new_value = strdup(value);
                if (!new_value)
                        return -ENOMEM;

                old_value = ordered_hashmap_get2(*properties, key, (void**) &old_key);

                /* ordered_hashmap_replace() does not fail when the hashmap already has the entry. */
                r = ordered_hashmap_replace(*properties, new_key, new_value);
                if (r < 0)
                        return r;

                TAKE_PTR(new_key);
                TAKE_PTR(new_value);
        } else {
                _unused_ _cleanup_free_ char *old_value = NULL;
                _cleanup_free_ char *old_key = NULL;

                old_value = ordered_hashmap_remove2(*properties, key, (void**) &old_key);
        }

        if (!db) {
                device->properties_generation++;
                device->properties_buf_outdated = true;
        }

        return 0;
}

int device_set_syspath(sd_device *device, const char *_syspath, bool verify) {
        _cleanup_free_ char *syspath = NULL;
        const char *devpath;
        int r;

        assert(device);
        assert(_syspath);

        /* must be a subdirectory of /sys */
        if (!path_startswith(_syspath, "/sys/"))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "sd-device: Syspath '%s' is not a subdirectory of /sys",
                                       _syspath);

        if (verify) {
                _cleanup_close_ int fd = -1;

                r = chase_symlinks(_syspath, NULL, 0, &syspath, &fd);
                if (r == -ENOENT)
                         /* the device does not exist (any more?) */
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODEV),
                                               "sd-device: Failed to chase symlinks in \"%s\".", _syspath);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: Failed to get target of '%s': %m", _syspath);

                if (!path_startswith(syspath, "/sys")) {
                        _cleanup_free_ char *real_sys = NULL, *new_syspath = NULL;
                        char *p;

                        /* /sys is a symlink to somewhere sysfs is mounted on? In that case, we convert the path to real sysfs to "/sys". */
                        r = chase_symlinks("/sys", NULL, 0, &real_sys, NULL);
                        if (r < 0)
                                return log_debug_errno(r, "sd-device: Failed to chase symlink /sys: %m");

                        p = path_startswith(syspath, real_sys);
                        if (!p)
                                return log_debug_errno(SYNTHETIC_ERRNO(ENODEV),
                                                       "sd-device: Canonicalized path '%s' does not starts with sysfs mount point '%s'",
                                                       syspath, real_sys);

                        new_syspath = path_join("/sys", p);
                        if (!new_syspath)
                                return log_oom_debug();

                        free_and_replace(syspath, new_syspath);
                        path_simplify(syspath);
                }

                if (path_startswith(syspath, "/sys/devices/")) {
                        /* For proper devices, stricter rules apply: they must have a 'uevent' file,
                         * otherwise we won't allow them */

                        if (faccessat(fd, "uevent", F_OK, 0) < 0) {
                                if (errno == ENOENT)
                                        /* This is not a valid device.  Note, this condition is quite often
                                         * satisfied when enumerating devices or finding a parent device.
                                         * Hence, use log_trace_errno() here. */
                                        return log_trace_errno(SYNTHETIC_ERRNO(ENODEV),
                                                               "sd-device: the uevent file \"%s/uevent\" does not exist.", syspath);
                                if (errno == ENOTDIR)
                                        /* Not actually a directory. */
                                        return log_debug_errno(SYNTHETIC_ERRNO(ENODEV),
                                                               "sd-device: the syspath \"%s\" is not a directory.", syspath);

                                return log_debug_errno(errno, "sd-device: cannot find uevent file for %s: %m", syspath);
                        }
                } else {
                        struct stat st;

                        /* For everything else lax rules apply: they just need to be a directory */

                        if (fstat(fd, &st) < 0)
                                return log_debug_errno(errno, "sd-device: failed to check if syspath \"%s\" is a directory: %m", syspath);
                        if (!S_ISDIR(st.st_mode))
                                return log_debug_errno(SYNTHETIC_ERRNO(ENODEV),
                                                       "sd-device: the syspath \"%s\" is not a directory.", syspath);
                }

                /* Only operate on sysfs, i.e. refuse going down into /sys/fs/cgroup/ or similar places where
                 * things are not arranged as kobjects in kernel, and hence don't necessarily have
                 * kobject/attribute structure. */
                r = getenv_bool_secure("SYSTEMD_DEVICE_VERIFY_SYSFS");
                if (r < 0 && r != -ENXIO)
                        log_debug_errno(r, "Failed to parse $SYSTEMD_DEVICE_VERIFY_SYSFS value: %m");
                if (r != 0) {
                        r = fd_is_fs_type(fd, SYSFS_MAGIC);
                        if (r < 0)
                                return log_debug_errno(r, "sd-device: failed to check if syspath \"%s\" is backed by sysfs.", syspath);
                        if (r == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(ENODEV),
                                                       "sd-device: the syspath \"%s\" is outside of sysfs, refusing.", syspath);
                }
        } else {
                syspath = strdup(_syspath);
                if (!syspath)
                        return log_oom_debug();

                path_simplify(syspath);
        }

        assert_se(devpath = startswith(syspath, "/sys"));
        if (devpath[0] != '/')
                return log_debug_errno(SYNTHETIC_ERRNO(ENODEV), "sd-device: \"/sys\" alone is not a valid device path.");

        r = device_add_property_internal(device, "DEVPATH", devpath);
        if (r < 0)
                return log_debug_errno(r, "sd-device: Failed to add \"DEVPATH\" property for device \"%s\": %m", syspath);

        free_and_replace(device->syspath, syspath);
        device->devpath = devpath;
        return 0;
}

int device_set_devtype(sd_device *device, const char *devtype) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(device);
        assert(devtype);

        t = strdup(devtype);
        if (!t)
                return -ENOMEM;

        r = device_add_property_internal(device, "DEVTYPE", t);
        if (r < 0)
                return r;

        return free_and_replace(device->devtype, t);
}

int device_set_ifindex(sd_device *device, const char *name) {
        int r, ifindex;

        assert(device);
        assert(name);

        ifindex = parse_ifindex(name);
        if (ifindex < 0)
                return ifindex;

        r = device_add_property_internal(device, "IFINDEX", name);
        if (r < 0)
                return r;

        device->ifindex = ifindex;

        return 0;
}

int device_set_devname(sd_device *device, const char *devname) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(device);
        assert(devname);

        if (devname[0] != '/')
                t = strjoin("/dev/", devname);
        else
                t = strdup(devname);
        if (!t)
                return -ENOMEM;

        r = device_add_property_internal(device, "DEVNAME", t);
        if (r < 0)
                return r;

        return free_and_replace(device->devname, t);
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
        unsigned maj, min = 0;
        int r;

        assert(device);
        assert(major);

        r = safe_atou(major, &maj);
        if (r < 0)
                return r;
        if (maj == 0)
                return 0;
        if (!DEVICE_MAJOR_VALID(maj))
                return -EINVAL;

        if (minor) {
                r = safe_atou(minor, &min);
                if (r < 0)
                        return r;
                if (!DEVICE_MINOR_VALID(min))
                        return -EINVAL;
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

int device_set_diskseq(sd_device *device, const char *str) {
        uint64_t diskseq;
        int r;

        assert(device);
        assert(str);

        r = safe_atou64(str, &diskseq);
        if (r < 0)
                return r;
        if (diskseq == 0)
                return -EINVAL;

        r = device_add_property_internal(device, "DISKSEQ", str);
        if (r < 0)
                return r;

        device->diskseq = diskseq;

        return 0;
}

int device_set_subsystem(sd_device *device, const char *subsystem) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(device);

        if (subsystem) {
                s = strdup(subsystem);
                if (!s)
                        return -ENOMEM;
        }

        r = device_add_property_internal(device, "SUBSYSTEM", s);
        if (r < 0)
                return r;

        device->subsystem_set = true;
        return free_and_replace(device->subsystem, s);
}

int device_set_drivers_subsystem(sd_device *device) {
        _cleanup_free_ char *subsystem = NULL;
        const char *devpath, *drivers, *p;
        int r;

        assert(device);

        r = sd_device_get_devpath(device, &devpath);
        if (r < 0)
                return r;

        drivers = strstr(devpath, "/drivers/");
        if (!drivers)
                drivers = endswith(devpath, "/drivers");
        if (!drivers)
                return -EINVAL;

        /* Find the path component immediately before the "/drivers/" string */
        r = path_find_last_component(devpath, /* accept_dot_dot= */ false, &drivers, &p);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        subsystem = strndup(p, r);
        if (!subsystem)
                return -ENOMEM;

        r = device_set_subsystem(device, "drivers");
        if (r < 0)
                return r;

        return free_and_replace(device->driver_subsystem, subsystem);
}

int device_set_driver(sd_device *device, const char *driver) {
        _cleanup_free_ char *d = NULL;
        int r;

        assert(device);

        if (driver) {
                d = strdup(driver);
                if (!d)
                        return -ENOMEM;
        }

        r = device_add_property_internal(device, "DRIVER", d);
        if (r < 0)
                return r;

        device->driver_set = true;
        return free_and_replace(device->driver, d);
}

static bool is_valid_tag(const char *tag) {
        assert(tag);

        return !strchr(tag, ':') && !strchr(tag, ' ');
}

int device_add_tag(sd_device *device, const char *tag, bool both) {
        int r, added;

        assert(device);
        assert(tag);

        if (!is_valid_tag(tag))
                return -EINVAL;

        /* Definitely add to the "all" list of tags (i.e. the sticky list) */
        added = set_put_strdup(&device->all_tags, tag);
        if (added < 0)
                return added;

        /* And optionally, also add it to the current list of tags */
        if (both) {
                r = set_put_strdup(&device->current_tags, tag);
                if (r < 0) {
                        if (added > 0)
                                (void) set_remove(device->all_tags, tag);

                        return r;
                }
        }

        device->tags_generation++;
        device->property_tags_outdated = true;

        return 0;
}

int device_add_devlink(sd_device *device, const char *devlink) {
        int r;

        assert(device);
        assert(devlink);

        r = set_put_strdup(&device->devlinks, devlink);
        if (r < 0)
                return r;

        device->devlinks_generation++;
        device->property_devlinks_outdated = true;

        return 0;
}

bool device_has_devlink(sd_device *device, const char *devlink) {
        assert(device);
        assert(devlink);

        return set_contains(device->devlinks, devlink);
}

static int device_add_property_internal_from_string(sd_device *device, const char *str) {
        _cleanup_free_ char *key = NULL;
        char *value;
        int r;

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

        /* Add the property to both sd_device::properties and sd_device::properties_db,
         * as this is called by only handle_db_line(). */
        r = device_add_property_aux(device, key, value, false);
        if (r < 0)
                return r;

        return device_add_property_aux(device, key, value, true);
}

int device_set_usec_initialized(sd_device *device, usec_t when) {
        char s[DECIMAL_STR_MAX(usec_t)];
        int r;

        assert(device);

        xsprintf(s, USEC_FMT, when);

        r = device_add_property_internal(device, "USEC_INITIALIZED", s);
        if (r < 0)
                return r;

        device->usec_initialized = when;
        return 0;
}

int device_get_property_bool(sd_device *device, const char *key) {
        const char *value;
        int r;

        assert(device);
        assert(key);

        r = sd_device_get_property_value(device, key, &value);
        if (r < 0)
                return r;

        return parse_boolean(value);
}

int device_get_devnode_mode(sd_device *device, mode_t *ret) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devmode == MODE_INVALID)
                return -ENOENT;

        if (ret)
                *ret = device->devmode;

        return 0;
}

int device_get_devnode_uid(sd_device *device, uid_t *ret) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devuid == UID_INVALID)
                return -ENOENT;

        if (ret)
                *ret = device->devuid;

        return 0;
}

int device_get_devnode_gid(sd_device *device, gid_t *ret) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devgid == GID_INVALID)
                return -ENOENT;

        if (ret)
                *ret = device->devgid;

        return 0;
}

static int handle_db_line(sd_device *device, char key, const char *value) {
        int r;

        assert(device);
        assert(value);

        switch (key) {
        case 'G': /* Any tag */
        case 'Q': /* Current tag */
                return device_add_tag(device, value, key == 'Q');

        case 'S': {
                const char *path;

                path = strjoina("/dev/", value);
                return device_add_devlink(device, path);
        }
        case 'E':
                return device_add_property_internal_from_string(device, value);

        case 'I': {
                usec_t t;

                r = safe_atou64(value, &t);
                if (r < 0)
                        return r;

                return device_set_usec_initialized(device, t);
        }
        case 'L':
                return safe_atoi(value, &device->devlink_priority);

        case 'W':
                /* Deprecated. Previously, watch handle is both saved in database and /run/udev/watch.
                 * However, the handle saved in database may not be updated when the handle is updated
                 * or removed. Moreover, it is not necessary to store the handle within the database,
                 * as its value becomes meaningless when udevd is restarted. */
                return 0;

        case 'V':
                return safe_atou(value, &device->database_version);

        default:
                log_device_debug(device, "sd-device: Unknown key '%c' in device db, ignoring", key);
                return 0;
        }
}

int device_get_device_id(sd_device *device, const char **ret) {
        assert(device);
        assert(ret);

        if (!device->device_id) {
                _cleanup_free_ char *id = NULL;
                const char *subsystem;
                dev_t devnum;
                int ifindex, r;

                r = sd_device_get_subsystem(device, &subsystem);
                if (r < 0)
                        return r;

                if (sd_device_get_devnum(device, &devnum) >= 0) {
                        /* use dev_t — b259:131072, c254:0 */
                        if (asprintf(&id, "%c%u:%u",
                                     streq(subsystem, "block") ? 'b' : 'c',
                                     major(devnum), minor(devnum)) < 0)
                                return -ENOMEM;
                } else if (sd_device_get_ifindex(device, &ifindex) >= 0) {
                        /* use netdev ifindex — n3 */
                        if (asprintf(&id, "n%u", (unsigned) ifindex) < 0)
                                return -ENOMEM;
                } else {
                        _cleanup_free_ char *sysname = NULL;

                        /* use $subsys:$sysname — pci:0000:00:1f.2
                         * sd_device_get_sysname() has '!' translated, get it from devpath */
                        r = path_extract_filename(device->devpath, &sysname);
                        if (r < 0)
                                return r;
                        if (r == O_DIRECTORY)
                                return -EINVAL;

                        if (streq(subsystem, "drivers")) {
                                /* the 'drivers' pseudo-subsystem is special, and needs the real
                                 * subsystem encoded as well */
                                assert(device->driver_subsystem);
                                id = strjoin("+drivers:", device->driver_subsystem, ":", sysname);
                        } else
                                id = strjoin("+", subsystem, ":", sysname);
                        if (!id)
                                return -ENOMEM;
                }

                if (!filename_is_valid(id))
                        return -EINVAL;

                device->device_id = TAKE_PTR(id);
        }

        *ret = device->device_id;
        return 0;
}

int device_read_db_internal_filename(sd_device *device, const char *filename) {
        _cleanup_free_ char *db = NULL;
        const char *value;
        size_t db_len;
        char key = '\0';  /* Unnecessary initialization to appease gcc-12.0.0-0.4.fc36 */
        int r;

        enum {
                PRE_KEY,
                KEY,
                PRE_VALUE,
                VALUE,
                INVALID_LINE,
        } state = PRE_KEY;

        assert(device);
        assert(filename);

        r = read_full_file(filename, &db, &db_len);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                return log_device_debug_errno(device, r, "sd-device: Failed to read db '%s': %m", filename);
        }

        /* devices with a database entry are initialized */
        device->is_initialized = true;

        device->db_loaded = true;

        for (size_t i = 0; i < db_len; i++)
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
                                        log_device_debug_errno(device, r, "sd-device: Failed to handle db entry '%c:%s', ignoring: %m",
                                                               key, value);

                                state = PRE_KEY;
                        }

                        break;
                default:
                        return log_device_debug_errno(device, SYNTHETIC_ERRNO(EINVAL), "sd-device: invalid db syntax.");
                }

        return 0;
}

int device_read_db_internal(sd_device *device, bool force) {
        const char *id, *path;
        int r;

        assert(device);

        if (device->db_loaded || (!force && device->sealed))
                return 0;

        r = device_get_device_id(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/data/", id);

        return device_read_db_internal_filename(device, path);
}

static bool device_match_sysattr_value(sd_device *device, const char *sysattr, const char *match_value) {
        const char *value;

        assert(device);
        assert(sysattr);

        if (sd_device_get_sysattr_value(device, sysattr, &value) < 0)
                return false;

        if (!match_value)
                return true;

        if (fnmatch(match_value, value, 0) == 0)
                return true;

        return false;
}

bool device_match_sysattr(sd_device *device, Hashmap *match_sysattr, Hashmap *nomatch_sysattr) {
        const char *sysattr;
        const char *value;

        assert(device);

        HASHMAP_FOREACH_KEY(value, sysattr, match_sysattr)
                if (!device_match_sysattr_value(device, sysattr, value))
                        return false;

        HASHMAP_FOREACH_KEY(value, sysattr, nomatch_sysattr)
                if (device_match_sysattr_value(device, sysattr, value))
                        return false;

        return true;
}

bool device_match_parent(sd_device *device, Set *match_parent, Set *nomatch_parent) {
        const char *syspath_parent, *syspath;

        assert(device);

        if (sd_device_get_syspath(device, &syspath) < 0)
                return false;

        SET_FOREACH(syspath_parent, nomatch_parent)
                if (path_startswith(syspath, syspath_parent))
                        return false;

        if (set_isempty(match_parent))
                return true;

        SET_FOREACH(syspath_parent, match_parent)
                if (path_startswith(syspath, syspath_parent))
                        return true;

        return false;
}

static int handle_uevent_line(
                sd_device *device,
                const char *key,
                const char *value,
                const char **major,
                const char **minor) {

        assert(device);
        assert(key);
        assert(value);
        assert(major);
        assert(minor);

        if (streq(key, "DEVTYPE"))
                return device_set_devtype(device, value);
        if (streq(key, "IFINDEX"))
                return device_set_ifindex(device, value);
        if (streq(key, "DEVNAME"))
                return device_set_devname(device, value);
        if (streq(key, "DEVMODE"))
                return device_set_devmode(device, value);
        if (streq(key, "DISKSEQ"))
                return device_set_diskseq(device, value);
        if (streq(key, "MAJOR"))
                *major = value;
        else if (streq(key, "MINOR"))
                *minor = value;
        else
                return device_add_property_internal(device, key, value);

        return 0;
}

int device_read_uevent_file(sd_device *device) {
        _cleanup_free_ char *uevent = NULL;
        const char *syspath, *key = NULL, *value = NULL, *major = NULL, *minor = NULL;
        char *path;
        size_t uevent_len;
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

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        device->uevent_loaded = true;

        path = strjoina(syspath, "/uevent");

        r = read_full_virtual_file(path, &uevent, &uevent_len);
        if (r < 0) {
                /* The uevent files may be write-only, the device may be already removed, or the device
                 * may not have the uevent file. */
                if (r == -EACCES || ERRNO_IS_DEVICE_ABSENT(r))
                        return 0;

                return log_device_debug_errno(device, r, "sd-device: Failed to read uevent file '%s': %m", path);
        }

        for (size_t i = 0; i < uevent_len; i++)
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
                        assert_not_reached();
                }

        if (major) {
                r = device_set_devnum(device, major, minor);
                if (r < 0)
                        log_device_debug_errno(device, r, "sd-device: Failed to set 'MAJOR=%s' or 'MINOR=%s' from '%s', ignoring: %m", major, strna(minor), path);
        }

        return 0;
}

int device_set_action(sd_device *device, sd_device_action_t a) {
        int r;

        assert(device);
        assert(a >= 0 && a < _SD_DEVICE_ACTION_MAX);

        r = device_add_property_internal(device, "ACTION", device_action_to_string(a));
        if (r < 0)
                return r;

        device->action = a;

        return 0;
}

static const char* const device_action_table[_SD_DEVICE_ACTION_MAX] = {
        [SD_DEVICE_ADD]     = "add",
        [SD_DEVICE_REMOVE]  = "remove",
        [SD_DEVICE_CHANGE]  = "change",
        [SD_DEVICE_MOVE]    = "move",
        [SD_DEVICE_ONLINE]  = "online",
        [SD_DEVICE_OFFLINE] = "offline",
        [SD_DEVICE_BIND]    = "bind",
        [SD_DEVICE_UNBIND]  = "unbind",
};

DEFINE_STRING_TABLE_LOOKUP(device_action, sd_device_action_t);

void dump_device_action_table(void) {
        DUMP_STRING_TABLE(device_action, sd_device_action_t, _SD_DEVICE_ACTION_MAX);
}
