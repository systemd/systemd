/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <net/if.h>
#include <sys/types.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "device-internal.h"
#include "device-private.h"
#include "device-util.h"
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

int device_get_devnode_mode(sd_device *device, mode_t *ret) {
        int r;

        assert(device);

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

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

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devuid == UID_INVALID)
                return -ENOENT;

        if (ret)
                *ret = device->devuid;

        return 0;
}

int device_set_devuid(sd_device *device, const char *uid) {
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

int device_get_devnode_gid(sd_device *device, gid_t *ret) {
        int r;

        assert(device);

        r = device_read_uevent_file(device);
        if (r < 0)
                return r;

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devgid == GID_INVALID)
                return -ENOENT;

        if (ret)
                *ret = device->devgid;

        return 0;
}

int device_set_devgid(sd_device *device, const char *gid) {
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
                        if (isempty(word))
                                continue;

                        r = device_add_tag(device, word, streq(key, "CURRENT_TAGS"));
                        if (r < 0)
                                return log_device_debug_errno(device, r, "sd-device: Failed to add tag '%s': %m", word);
                }
        } else if (streq(key, "UDEV_DATABASE_VERSION")) {
                r = safe_atou(value, &device->database_version);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to parse udev database version '%s': %m", value);
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

        if (device_in_subsystem(device, "drivers")) {
                r = device_set_drivers_subsystem(device);
                if (r < 0)
                        return log_device_debug_errno(device, r,
                                                      "sd-device: Failed to set driver subsystem: %m");
        }

        device->sealed = true;

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

int device_new_from_nulstr(sd_device **ret, char *nulstr, size_t len) {
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

                key = nulstr + i;
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
        _cleanup_free_ char **buf_strv = NULL, *buf_nulstr = NULL;
        size_t nulstr_len = 0, num = 0;

        assert(device);

        if (!device->properties_buf_outdated)
                return 0;

        /* append udev database version */
        buf_nulstr = newdup(char, "UDEV_DATABASE_VERSION=" STRINGIFY(LATEST_UDEV_DATABASE_VERSION) "\0",
                            STRLEN("UDEV_DATABASE_VERSION=" STRINGIFY(LATEST_UDEV_DATABASE_VERSION)) + 2);
        if (!buf_nulstr)
                return -ENOMEM;

        nulstr_len += STRLEN("UDEV_DATABASE_VERSION=" STRINGIFY(LATEST_UDEV_DATABASE_VERSION)) + 1;
        num++;

        FOREACH_DEVICE_PROPERTY(device, prop, val) {
                size_t len = 0;

                len = strlen(prop) + 1 + strlen(val);

                buf_nulstr = GREEDY_REALLOC0(buf_nulstr, nulstr_len + len + 2);
                if (!buf_nulstr)
                        return -ENOMEM;

                strscpyl(buf_nulstr + nulstr_len, len + 1, prop, "=", val, NULL);
                nulstr_len += len + 1;
                num++;
        }

        /* build buf_strv from buf_nulstr */
        buf_strv = new0(char*, num + 1);
        if (!buf_strv)
                return -ENOMEM;

        size_t i = 0;
        NULSTR_FOREACH(p, buf_nulstr)
                buf_strv[i++] = p;
        assert(i == num);

        free_and_replace(device->properties_nulstr, buf_nulstr);
        device->properties_nulstr_len = nulstr_len;
        free_and_replace(device->properties_strv, buf_strv);

        device->properties_buf_outdated = false;
        return 0;
}

int device_get_properties_nulstr(sd_device *device, const char **ret_nulstr, size_t *ret_len) {
        int r;

        assert(device);

        r = device_update_properties_bufs(device);
        if (r < 0)
                return r;

        if (ret_nulstr)
                *ret_nulstr = device->properties_nulstr;
        if (ret_len)
                *ret_len = device->properties_nulstr_len;

        return 0;
}

int device_get_properties_strv(sd_device *device, char ***ret) {
        int r;

        assert(device);

        r = device_update_properties_bufs(device);
        if (r < 0)
                return r;

        if (ret)
                *ret = device->properties_strv;

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

int device_clone_with_db(sd_device *device, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dest = NULL;
        const char *key, *val;
        int r;

        assert(device);
        assert(ret);

        /* The device may be already removed. Let's copy minimal set of information that was obtained through
         * netlink socket. */

        r = device_new_aux(&dest);
        if (r < 0)
                return r;

        /* Seal device to prevent reading the uevent file, as the device may have been already removed. */
        dest->sealed = true;

        /* Copy syspath, then also devname, sysname or sysnum can be obtained. */
        r = device_set_syspath(dest, device->syspath, false);
        if (r < 0)
                return r;

        /* Copy other information stored in database. Here, do not use FOREACH_DEVICE_PROPERTY() and
         * sd_device_get_property_value(), as they calls device_properties_prepare() ->
         * device_read_uevent_file(), but as commented in the above, the device may be already removed and
         * reading uevent file may fail. */
        ORDERED_HASHMAP_FOREACH_KEY(val, key, device->properties) {
                if (streq(key, "MINOR"))
                        continue;

                if (streq(key, "MAJOR")) {
                        const char *minor = NULL;

                        minor = ordered_hashmap_get(device->properties, "MINOR");
                        r = device_set_devnum(dest, val, minor);
                } else
                        r = device_amend(dest, key, val);
                if (r < 0)
                        return r;

                if (streq(key, "SUBSYSTEM") && streq(val, "drivers")) {
                        r = free_and_strdup(&dest->driver_subsystem, device->driver_subsystem);
                        if (r < 0)
                                return r;
                }
        }

        /* Finally, read the udev database. */
        r = device_read_db_internal(dest, /* force = */ true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dest);
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

        r = sd_device_get_device_id(device, &id);
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

bool device_should_have_db(sd_device *device) {
        assert(device);

        if (device_has_info(device))
                return true;

        if (major(device->devnum) != 0)
                return true;

        if (device->ifindex != 0)
                return true;

        return false;
}

void device_set_db_persist(sd_device *device) {
        assert(device);

        device->db_persist = true;
}

static int device_get_db_path(sd_device *device, char **ret) {
        const char *id;
        char *path;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_device_id(device, &id);
        if (r < 0)
                return r;

        path = path_join("/run/udev/data/", id);
        if (!path)
                return -ENOMEM;

        *ret = path;
        return 0;
}

int device_has_db(sd_device *device) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(device);

        r = device_get_db_path(device, &path);
        if (r < 0)
                return r;

        return access(path, F_OK) >= 0;
}

int device_update_db(sd_device *device) {
        _cleanup_(unlink_and_freep) char *path = NULL, *path_tmp = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(device);

        /* do not store anything for otherwise empty devices */
        if (!device_should_have_db(device))
                return device_delete_db(device);

        r = device_get_db_path(device, &path);
        if (r < 0)
                return r;

        /* write a database file */
        r = mkdir_parents(path, 0755);
        if (r < 0)
                return log_device_debug_errno(device, r,
                                              "sd-device: Failed to create parent directories of '%s': %m",
                                              path);

        r = fopen_temporary(path, &f, &path_tmp);
        if (r < 0)
                return log_device_debug_errno(device, r,
                                              "sd-device: Failed to create temporary file for database file '%s': %m",
                                              path);

        /* set 'sticky' bit to indicate that we should not clean the database when we transition from initrd
         * to the real root */
        if (fchmod(fileno(f), device->db_persist ? 01644 : 0644) < 0)
                return log_device_debug_errno(device, errno,
                                              "sd-device: Failed to chmod temporary database file '%s': %m",
                                              path_tmp);

        if (device_has_info(device)) {
                const char *property, *value, *ct;

                if (major(device->devnum) > 0) {
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

                SET_FOREACH(ct, device->current_tags)
                        fprintf(f, "Q:%s\n", ct); /* Current tag */

                /* Always write the latest database version here, instead of the value stored in
                 * device->database_version, as which may be 0. */
                fputs("V:" STRINGIFY(LATEST_UDEV_DATABASE_VERSION) "\n", f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                return log_device_debug_errno(device, r,
                                              "sd-device: Failed to flush temporary database file '%s': %m",
                                              path_tmp);

        if (rename(path_tmp, path) < 0)
                return log_device_debug_errno(device, errno,
                                              "sd-device: Failed to rename temporary database file '%s' to '%s': %m",
                                              path_tmp, path);

        log_device_debug(device, "sd-device: Created database file '%s' for '%s'.", path, device->devpath);

        path_tmp = mfree(path_tmp);
        path = mfree(path);

        return 0;
}

int device_delete_db(sd_device *device) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(device);

        r = device_get_db_path(device, &path);
        if (r < 0)
                return r;

        if (unlink(path) < 0 && errno != ENOENT)
                return -errno;

        return 0;
}

int device_read_db_internal(sd_device *device, bool force) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(device);

        if (device->db_loaded || (!force && device->sealed))
                return 0;

        r = device_get_db_path(device, &path);
        if (r < 0)
                return r;

        return device_read_db_internal_filename(device, path);
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
