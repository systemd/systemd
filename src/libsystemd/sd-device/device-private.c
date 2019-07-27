/* SPDX-License-Identifier: LGPL-2.1+ */

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

int device_get_devnode_mode(sd_device *device, mode_t *mode) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devmode == (mode_t) -1)
                return -ENOENT;

        if (mode)
                *mode = device->devmode;

        return 0;
}

int device_get_devnode_uid(sd_device *device, uid_t *uid) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devuid == (uid_t) -1)
                return -ENOENT;

        if (uid)
                *uid = device->devuid;

        return 0;
}

static int device_set_devuid(sd_device *device, const char *uid) {
        unsigned u;
        int r;

        assert(device);
        assert(uid);

        r = safe_atou(uid, &u);
        if (r < 0)
                return r;

        r = device_add_property_internal(device, "DEVUID", uid);
        if (r < 0)
                return r;

        device->devuid = u;

        return 0;
}

int device_get_devnode_gid(sd_device *device, gid_t *gid) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->devgid == (gid_t) -1)
                return -ENOENT;

        if (gid)
                *gid = device->devgid;

        return 0;
}

static int device_set_devgid(sd_device *device, const char *gid) {
        unsigned g;
        int r;

        assert(device);
        assert(gid);

        r = safe_atou(gid, &g);
        if (r < 0)
                return r;

        r = device_add_property_internal(device, "DEVGID", gid);
        if (r < 0)
                return r;

        device->devgid = g;

        return 0;
}

int device_get_action(sd_device *device, DeviceAction *action) {
        assert(device);

        if (device->action < 0)
                return -ENOENT;

        if (action)
                *action = device->action;

        return 0;
}

static int device_set_action(sd_device *device, const char *action) {
        DeviceAction a;
        int r;

        assert(device);
        assert(action);

        a = device_action_from_string(action);
        if (a < 0)
                return -EINVAL;

        r = device_add_property_internal(device, "ACTION", action);
        if (r < 0)
                return r;

        device->action = a;

        return 0;
}

int device_get_seqnum(sd_device *device, uint64_t *seqnum) {
        assert(device);

        if (device->seqnum == 0)
                return -ENOENT;

        if (seqnum)
                *seqnum = device->seqnum;

        return 0;
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
                r = device_set_action(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set action to '%s': %m", value);
        } else if (streq(key, "SEQNUM")) {
                r = device_set_seqnum(device, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set SEQNUM to '%s': %m", value);
        } else if (streq(key, "DEVLINKS")) {
                const char *word, *state;
                size_t l;

                FOREACH_WORD(word, l, value, state) {
                        char devlink[l + 1];

                        strncpy(devlink, word, l);
                        devlink[l] = '\0';

                        r = device_add_devlink(device, devlink);
                        if (r < 0)
                                return log_device_debug_errno(device, r, "sd-device: Failed to add devlink '%s': %m", devlink);
                }
        } else if (streq(key, "TAGS")) {
                const char *word, *state;
                size_t l;

                FOREACH_WORD_SEPARATOR(word, l, value, ":", state) {
                        char tag[l + 1];

                        (void) strncpy(tag, word, l);
                        tag[l] = '\0';

                        r = device_add_tag(device, tag);
                        if (r < 0)
                                return log_device_debug_errno(device, r, "sd-device: Failed to add tag '%s': %m", tag);
                }
        } else {
                r = device_add_property_internal(device, key, value);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to add property '%s=%s': %m", key, value);
        }

        return 0;
}

static int device_append(sd_device *device, char *key, const char **_major, const char **_minor) {
        const char *major = NULL, *minor = NULL;
        char *value;
        int r;

        assert(device);
        assert(key);
        assert(_major);
        assert(_minor);

        value = strchr(key, '=');
        if (!value) {
                log_device_debug(device, "sd-device: Not a key-value pair: '%s'", key);
                return -EINVAL;
        }

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

        if (major != 0)
                *_major = major;

        if (minor != 0)
                *_minor = minor;

        return 0;
}

void device_seal(sd_device *device) {
        assert(device);

        device->sealed = true;
}

static int device_verify(sd_device *device) {
        assert(device);

        if (!device->devpath || !device->subsystem || device->action < 0 || device->seqnum == 0) {
                log_device_debug(device, "sd-device: Device created from strv or nulstr lacks devpath, subsystem, action or seqnum.");
                return -EINVAL;
        }

        device->sealed = true;

        return 0;
}

int device_new_from_strv(sd_device **ret, char **strv) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        char **key;
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

int device_new_from_nulstr(sd_device **ret, uint8_t *nulstr, size_t len) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *major = NULL, *minor = NULL;
        unsigned i = 0;
        int r;

        assert(ret);
        assert(nulstr);
        assert(len);

        r = device_new_aux(&device);
        if (r < 0)
                return r;

        while (i < len) {
                char *key;
                const char *end;

                key = (char*)&nulstr[i];
                end = memchr(key, '\0', len - i);
                if (!end) {
                        log_device_debug(device, "sd-device: Failed to parse nulstr");
                        return -EINVAL;
                }
                i += end - key + 1;

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
        size_t allocated_nulstr = 0;
        size_t nulstr_len = 0, num = 0, i = 0;

        assert(device);

        if (!device->properties_buf_outdated)
                return 0;

        FOREACH_DEVICE_PROPERTY(device, prop, val) {
                size_t len = 0;

                len = strlen(prop) + 1 + strlen(val);

                buf_nulstr = GREEDY_REALLOC0(buf_nulstr, allocated_nulstr, nulstr_len + len + 2);
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

int device_get_devlink_priority(sd_device *device, int *priority) {
        int r;

        assert(device);
        assert(priority);

        r = device_read_db(device);
        if (r < 0)
                return r;

        *priority = device->devlink_priority;

        return 0;
}

int device_get_watch_handle(sd_device *device, int *handle) {
        int r;

        assert(device);

        r = device_read_db(device);
        if (r < 0)
                return r;

        if (device->watch_handle < 0)
                return -ENOENT;

        if (handle)
                *handle = device->watch_handle;

        return 0;
}

void device_set_watch_handle(sd_device *device, int handle) {
        assert(device);

        device->watch_handle = handle;
}

int device_rename(sd_device *device, const char *name) {
        _cleanup_free_ char *dirname = NULL;
        const char *new_syspath, *interface;
        int r;

        assert(device);
        assert(name);

        dirname = dirname_malloc(device->syspath);
        if (!dirname)
                return -ENOMEM;

        new_syspath = prefix_roota(dirname, name);

        /* the user must trust that the new name is correct */
        r = device_set_syspath(device, new_syspath, false);
        if (r < 0)
                return r;

        r = sd_device_get_property_value(device, "INTERFACE", &interface);
        if (r >= 0) {
                /* like DEVPATH_OLD, INTERFACE_OLD is not saved to the db, but only stays around for the current event */
                r = device_add_property_internal(device, "INTERFACE_OLD", interface);
                if (r < 0)
                        return r;

                r = device_add_property_internal(device, "INTERFACE", name);
                if (r < 0)
                        return r;
        } else if (r != -ENOENT)
                return r;

        return 0;
}

int device_shallow_clone(sd_device *old_device, sd_device **new_device) {
        _cleanup_(sd_device_unrefp) sd_device *ret = NULL;
        int r;

        assert(old_device);
        assert(new_device);

        r = device_new_aux(&ret);
        if (r < 0)
                return r;

        r = device_set_syspath(ret, old_device->syspath, false);
        if (r < 0)
                return r;

        r = device_set_subsystem(ret, old_device->subsystem);
        if (r < 0)
                return r;

        ret->devnum = old_device->devnum;

        *new_device = TAKE_PTR(ret);

        return 0;
}

int device_clone_with_db(sd_device *old_device, sd_device **new_device) {
        _cleanup_(sd_device_unrefp) sd_device *ret = NULL;
        int r;

        assert(old_device);
        assert(new_device);

        r = device_shallow_clone(old_device, &ret);
        if (r < 0)
                return r;

        r = device_read_db(ret);
        if (r < 0)
                return r;

        ret->sealed = true;

        *new_device = TAKE_PTR(ret);

        return 0;
}

int device_new_from_synthetic_event(sd_device **new_device, const char *syspath, const char *action) {
        _cleanup_(sd_device_unrefp) sd_device *ret = NULL;
        int r;

        assert(new_device);
        assert(syspath);
        assert(action);

        r = sd_device_new_from_syspath(&ret, syspath);
        if (r < 0)
                return r;

        r = device_read_uevent_file(ret);
        if (r < 0)
                return r;

        r = device_set_action(ret, action);
        if (r < 0)
                return r;

        *new_device = TAKE_PTR(ret);

        return 0;
}

int device_new_from_stat_rdev(sd_device **ret, const struct stat *st) {
        char type;

        assert(ret);
        assert(st);

        if (S_ISBLK(st->st_mode))
                type = 'b';
        else if (S_ISCHR(st->st_mode))
                type = 'c';
        else
                return -ENOTTY;

        return sd_device_new_from_devnum(ret, type, st->st_rdev);
}

int device_copy_properties(sd_device *device_dst, sd_device *device_src) {
        const char *property, *value;
        Iterator i;
        int r;

        assert(device_dst);
        assert(device_src);

        r = device_properties_prepare(device_src);
        if (r < 0)
                return r;

        ORDERED_HASHMAP_FOREACH_KEY(value, property, device_src->properties_db, i) {
                r = device_add_property_aux(device_dst, property, value, true);
                if (r < 0)
                        return r;
        }

        ORDERED_HASHMAP_FOREACH_KEY(value, property, device_src->properties, i) {
                r = device_add_property_aux(device_dst, property, value, false);
                if (r < 0)
                        return r;
        }

        return 0;
}

void device_cleanup_tags(sd_device *device) {
        assert(device);

        set_free_free(device->tags);
        device->tags = NULL;
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

        free(set_remove(device->tags, tag));
        device->property_tags_outdated = true;
        device->tags_generation++;
}

static int device_tag(sd_device *device, const char *tag, bool add) {
        const char *id;
        char *path;
        int r;

        assert(device);
        assert(tag);

        r = device_get_id_filename(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/tags/", tag, "/", id);

        if (add) {
                r = touch_file(path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0444);
                if (r < 0)
                        return r;
        } else {
                r = unlink(path);
                if (r < 0 && errno != ENOENT)
                        return -errno;
        }

        return 0;
}

int device_tag_index(sd_device *device, sd_device *device_old, bool add) {
        const char *tag;
        int r = 0, k;

        if (add && device_old) {
                /* delete possible left-over tags */
                FOREACH_DEVICE_TAG(device_old, tag) {
                        if (!sd_device_has_tag(device, tag)) {
                                k = device_tag(device_old, tag, false);
                                if (r >= 0 && k < 0)
                                        r = k;
                        }
                }
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

        if (!set_isempty(device->tags))
                return true;

        if (device->watch_handle >= 0)
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

        r = device_get_id_filename(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/data/", id);

        /* do not store anything for otherwise empty devices */
        if (!has_info && major(device->devnum) == 0 && device->ifindex == 0) {
                r = unlink(path);
                if (r < 0 && errno != ENOENT)
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
        if (device->db_persist) {
                r = fchmod(fileno(f), 01644);
                if (r < 0) {
                        r = -errno;
                        goto fail;
                }
        } else {
                r = fchmod(fileno(f), 0644);
                if (r < 0) {
                        r = -errno;
                        goto fail;
                }
        }

        if (has_info) {
                const char *property, *value, *tag;
                Iterator i;

                if (major(device->devnum) > 0) {
                        const char *devlink;

                        FOREACH_DEVICE_DEVLINK(device, devlink)
                                fprintf(f, "S:%s\n", devlink + STRLEN("/dev/"));

                        if (device->devlink_priority != 0)
                                fprintf(f, "L:%i\n", device->devlink_priority);

                        if (device->watch_handle >= 0)
                                fprintf(f, "W:%i\n", device->watch_handle);
                }

                if (device->usec_initialized > 0)
                        fprintf(f, "I:"USEC_FMT"\n", device->usec_initialized);

                ORDERED_HASHMAP_FOREACH_KEY(value, property, device->properties_db, i)
                        fprintf(f, "E:%s=%s\n", property, value);

                FOREACH_DEVICE_TAG(device, tag)
                        fprintf(f, "G:%s\n", tag);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        r = rename(path_tmp, path);
        if (r < 0) {
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

        r = device_get_id_filename(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/data/", id);

        r = unlink(path);
        if (r < 0 && errno != ENOENT)
                return -errno;

        return 0;
}

static const char* const device_action_table[_DEVICE_ACTION_MAX] = {
        [DEVICE_ACTION_ADD]     = "add",
        [DEVICE_ACTION_REMOVE]  = "remove",
        [DEVICE_ACTION_CHANGE]  = "change",
        [DEVICE_ACTION_MOVE]    = "move",
        [DEVICE_ACTION_ONLINE]  = "online",
        [DEVICE_ACTION_OFFLINE] = "offline",
        [DEVICE_ACTION_BIND]    = "bind",
        [DEVICE_ACTION_UNBIND]  = "unbind",
};

DEFINE_STRING_TABLE_LOOKUP(device_action, DeviceAction);

void dump_device_action_table(void) {
        DUMP_STRING_TABLE(device_action, DeviceAction, _DEVICE_ACTION_MAX);
}
