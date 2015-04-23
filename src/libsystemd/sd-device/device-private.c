/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2014 Tom Gundersen <teg@jklm.no>

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

#include <ctype.h>
#include <sys/types.h>
#include <net/if.h>

#include "util.h"
#include "macro.h"
#include "refcnt.h"
#include "path-util.h"
#include "strxcpyx.h"
#include "fileio.h"
#include "hashmap.h"
#include "set.h"
#include "strv.h"
#include "mkdir.h"

#include "sd-device.h"

#include "device-util.h"
#include "device-internal.h"
#include "device-private.h"

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

static int handle_db_line(sd_device *device, char key, const char *value) {
        char *path;
        int r;

        assert(device);
        assert(value);

        switch (key) {
        case 'S':
                path = strjoina("/dev/", value);
                r = device_add_devlink(device, path);
                if (r < 0)
                        return r;

                break;
        case 'L':
                r = safe_atoi(value, &device->devlink_priority);
                if (r < 0)
                        return r;

                break;
        case 'E':
                r = device_add_property_internal_from_string(device, value);
                if (r < 0)
                        return r;

                break;
        case 'G':
                r = device_add_tag(device, value);
                if (r < 0)
                        return r;

                break;
        case 'W':
                r = safe_atoi(value, &device->watch_handle);
                if (r < 0)
                        return r;

                break;
        case 'I':
                r = device_set_usec_initialized(device, value);
                if (r < 0)
                        return r;

                break;
        default:
                log_debug("device db: unknown key '%c'", key);
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
        char num[DECIMAL_STR_MAX(usec_t)];
        usec_t usec_initialized;
        int r;

        assert(device);

        if (device_old && device_old->usec_initialized > 0)
                usec_initialized = device_old->usec_initialized;
        else
                usec_initialized = now(CLOCK_MONOTONIC);

        r = snprintf(num, sizeof(num), USEC_FMT, usec_initialized);
        if (r < 0)
                return -errno;

        r = device_set_usec_initialized(device, num);
        if (r < 0)
                return r;

        return 0;
}

static int device_read_db(sd_device *device) {
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

        assert(device);

        if (device->db_loaded || device->sealed)
                return 0;

        r = device_get_id_filename(device, &id);
        if (r < 0)
                return r;

        path = strjoina("/run/udev/data/", id);

        r = read_full_file(path, &db, &db_len);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;
                else {
                        log_debug("sd-device: failed to read db '%s': %s", path, strerror(-r));
                        return r;
                }
        }

        /* devices with a database entry are initialized */
        device_set_is_initialized(device);

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
                                log_debug("sd-device: ignoring invalid db entry with key '%c'", key);

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
                                        log_debug("sd-device: failed to handle db entry '%c:%s': %s", key, value, strerror(-r));

                                state = PRE_KEY;
                        }

                        break;
                default:
                        assert_not_reached("invalid state when parsing db");
                }
        }

        device->db_loaded = true;

        return 0;
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
        assert(mode);

        r = device_read_db(device);
        if (r < 0)
                return r;

        *mode = device->devmode;

        return 0;
}

int device_get_devnode_uid(sd_device *device, uid_t *uid) {
        int r;

        assert(device);
        assert(uid);

        r = device_read_db(device);
        if (r < 0)
                return r;

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
        assert(gid);

        r = device_read_db(device);
        if (r < 0)
                return r;

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
                        return log_debug_errno(r, "sd-device: could not set syspath to '%s': %m", path);
        } else if (streq(key, "SUBSYSTEM")) {
                r = device_set_subsystem(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set subsystem to '%s': %m", value);
        } else if (streq(key, "DEVTYPE")) {
                r = device_set_devtype(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set devtype to '%s': %m", value);
        } else if (streq(key, "DEVNAME")) {
                r = device_set_devname(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set devname to '%s': %m", value);
        } else if (streq(key, "USEC_INITIALIZED")) {
                r = device_set_usec_initialized(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set usec-initialized to '%s': %m", value);
        } else if (streq(key, "DRIVER")) {
                r = device_set_driver(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set driver to '%s': %m", value);
        } else if (streq(key, "IFINDEX")) {
                r = device_set_ifindex(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set ifindex to '%s': %m", value);
        } else if (streq(key, "DEVMODE")) {
                r = device_set_devmode(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set devmode to '%s': %m", value);
        } else if (streq(key, "DEVUID")) {
                r = device_set_devuid(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set devuid to '%s': %m", value);
        } else if (streq(key, "DEVGID")) {
                r = device_set_devgid(device, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set devgid to '%s': %m", value);
        } else if (streq(key, "DEVLINKS")) {
                const char *word, *state;
                size_t l;

                FOREACH_WORD(word, l, value, state) {
                        char devlink[l + 1];

                        strncpy(devlink, word, l);
                        devlink[l] = '\0';

                        r = device_add_devlink(device, devlink);
                        if (r < 0)
                                return log_debug_errno(r, "sd-device: could not add devlink '%s': %m", devlink);
                }
        } else if (streq(key, "TAGS")) {
                const char *word, *state;
                size_t l;

                FOREACH_WORD_SEPARATOR(word, l, value, ":", state) {
                        char tag[l + 1];

                        (void)strncpy(tag, word, l);
                        tag[l] = '\0';

                        r = device_add_tag(device, tag);
                        if (r < 0)
                                return log_debug_errno(r, "sd-device: could not add tag '%s': %m", tag);
                }
        } else {
                r = device_add_property_internal(device, key, value);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not add property '%s=%s': %m", key, value);
        }

        return 0;
}

static const char* const device_action_table[_DEVICE_ACTION_MAX] = {
        [DEVICE_ACTION_ADD] = "add",
        [DEVICE_ACTION_REMOVE] = "remove",
        [DEVICE_ACTION_CHANGE] = "change",
        [DEVICE_ACTION_MOVE] = "move",
        [DEVICE_ACTION_ONLINE] = "online",
        [DEVICE_ACTION_OFFLINE] = "offline",
};

DEFINE_STRING_TABLE_LOOKUP(device_action, DeviceAction);

static int device_append(sd_device *device, char *key, const char **_major, const char **_minor, uint64_t *_seqnum,
                         DeviceAction *_action) {
        DeviceAction action = _DEVICE_ACTION_INVALID;
        uint64_t seqnum = 0;
        const char *major = NULL, *minor = NULL;
        char *value;
        int r;

        assert(device);
        assert(key);
        assert(_major);
        assert(_minor);
        assert(_seqnum);
        assert(_action);

        value = strchr(key, '=');
        if (!value) {
                log_debug("sd-device: not a key-value pair: '%s'", key);
                return -EINVAL;
        }

        *value = '\0';

        value++;

        if (streq(key, "MAJOR"))
                major = value;
        else if (streq(key, "MINOR"))
                minor = value;
        else {
                if (streq(key, "ACTION")) {
                        action = device_action_from_string(value);
                        if (action == _DEVICE_ACTION_INVALID)
                                return -EINVAL;
                } else if (streq(key, "SEQNUM")) {
                        r = safe_atou64(value, &seqnum);
                        if (r < 0)
                                return r;
                        else if (seqnum == 0)
                                 /* kernel only sends seqnum > 0 */
                                return -EINVAL;
                }

                r = device_amend(device, key, value);
                if (r < 0)
                        return r;
        }

        if (major != 0)
                *_major = major;

        if (minor != 0)
                *_minor = minor;

        if (action != _DEVICE_ACTION_INVALID)
                *_action = action;

        if (seqnum > 0)
                *_seqnum = seqnum;

        return 0;
}

void device_seal(sd_device *device) {
        assert(device);

        device->sealed = true;
}

static int device_verify(sd_device *device, DeviceAction action, uint64_t seqnum) {
        assert(device);

        if (!device->devpath || !device->subsystem || action == _DEVICE_ACTION_INVALID || seqnum == 0) {
                log_debug("sd-device: device created from strv lacks devpath, subsystem, action or seqnum");
                return -EINVAL;
        }

        device->sealed = true;

        return 0;
}

int device_new_from_strv(sd_device **ret, char **strv) {
        _cleanup_device_unref_ sd_device *device = NULL;
        char **key;
        const char *major = NULL, *minor = NULL;
        DeviceAction action = _DEVICE_ACTION_INVALID;
        uint64_t seqnum;
        int r;

        assert(ret);
        assert(strv);

        r = device_new_aux(&device);
        if (r < 0)
                return r;

        STRV_FOREACH(key, strv) {
                r = device_append(device, *key, &major, &minor, &seqnum, &action);
                if (r < 0)
                        return r;
        }

        if (major) {
                r = device_set_devnum(device, major, minor);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set devnum %s:%s: %m", major, minor);
        }

        r = device_verify(device, action, seqnum);
        if (r < 0)
                return r;

        *ret = device;
        device = NULL;

        return 0;
}

int device_new_from_nulstr(sd_device **ret, uint8_t *nulstr, size_t len) {
        _cleanup_device_unref_ sd_device *device = NULL;
        const char *major = NULL, *minor = NULL;
        DeviceAction action = _DEVICE_ACTION_INVALID;
        uint64_t seqnum;
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
                        log_debug("sd-device: failed to parse nulstr");
                        return -EINVAL;
                }
                i += end - key + 1;

                r = device_append(device, key, &major, &minor, &seqnum, &action);
                if (r < 0)
                        return r;
        }

        if (major) {
                r = device_set_devnum(device, major, minor);
                if (r < 0)
                        return log_debug_errno(r, "sd-device: could not set devnum %s:%s: %m", major, minor);
        }

        r = device_verify(device, action, seqnum);
        if (r < 0)
                return r;

        *ret = device;
        device = NULL;

        return 0;
}

static int device_update_properties_bufs(sd_device *device) {
        const char *val, *prop;
        char **buf_strv = NULL;
        uint8_t *buf_nulstr = NULL;
        size_t allocated_nulstr = 0, allocated_strv = 0;
        size_t nulstr_len = 0, strv_size = 0;

        assert(device);

        if (!device->properties_buf_outdated)
                return 0;

        FOREACH_DEVICE_PROPERTY(device, prop, val) {
                size_t len = 0;

                len = strlen(prop) + 1 + strlen(val);

                buf_nulstr = GREEDY_REALLOC0(buf_nulstr, allocated_nulstr, nulstr_len + len + 2);
                if (!buf_nulstr)
                        return -ENOMEM;

                buf_strv = GREEDY_REALLOC0(buf_strv, allocated_strv, strv_size + 2);
                if (!buf_strv)
                        return -ENOMEM;

                buf_strv[++ strv_size] = (char *)&buf_nulstr[nulstr_len];
                strscpyl((char *)buf_nulstr + nulstr_len, len + 1, prop, "=", val, NULL);
                nulstr_len += len + 1;
        }

        free(device->properties_nulstr);
        free(device->properties_strv);
        device->properties_nulstr = buf_nulstr;
        device->properties_nulstr_len = nulstr_len;
        device->properties_strv = buf_strv;

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
        assert(handle);

        r = device_read_db(device);
        if (r < 0)
                return r;

        *handle = device->watch_handle;

        return 0;
}

void device_set_watch_handle(sd_device *device, int handle) {
        assert(device);

        device->watch_handle = handle;
}

int device_rename(sd_device *device, const char *name) {
        _cleanup_free_ char *dirname = NULL;
        char *new_syspath;
        const char *interface;
        int r;

        assert(device);
        assert(name);

        dirname = dirname_malloc(device->syspath);
        if (!dirname)
                return -ENOMEM;

        new_syspath = strjoina(dirname, "/", name);

        /* the user must trust that the new name is correct */
        r = device_set_syspath(device, new_syspath, false);
        if (r < 0)
                return r;

        r = sd_device_get_property_value(device, "INTERFACE", &interface);
        if (r >= 0) {
                r = device_add_property_internal(device, "INTERFACE", name);
                if (r < 0)
                        return r;

                /* like DEVPATH_OLD, INTERFACE_OLD is not saved to the db, but only stays around for the current event */
                r = device_add_property_internal(device, "INTERFACE_OLD", interface);
                if (r < 0)
                        return r;
        } else if (r != -ENOENT)
                return r;

        return 0;
}

int device_shallow_clone(sd_device *old_device, sd_device **new_device) {
        _cleanup_device_unref_ sd_device *ret = NULL;
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

        *new_device = ret;
        ret = NULL;

        return 0;
}

int device_clone_with_db(sd_device *old_device, sd_device **new_device) {
        _cleanup_device_unref_ sd_device *ret = NULL;
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

        *new_device = ret;
        ret = NULL;

        return 0;
}

int device_new_from_synthetic_event(sd_device **new_device, const char *syspath, const char *action) {
        _cleanup_device_unref_ sd_device *ret = NULL;
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

        r = device_add_property_internal(ret, "ACTION", action);
        if (r < 0)
                return r;

        *new_device = ret;
        ret = NULL;

        return 0;
}

int device_copy_properties(sd_device *device_dst, sd_device *device_src) {
        const char *property, *value;
        int r;

        assert(device_dst);
        assert(device_src);

        FOREACH_DEVICE_PROPERTY(device_src, property, value) {
                r = device_add_property(device_dst, property, value);
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
        device->tags_generation ++;
}

void device_cleanup_devlinks(sd_device *device) {
        assert(device);

        set_free_free(device->devlinks);
        device->devlinks = NULL;
        device->property_devlinks_outdated = true;
        device->devlinks_generation ++;
}

void device_remove_tag(sd_device *device, const char *tag) {
        assert(device);
        assert(tag);

        free(set_remove(device->tags, tag));
        device->property_tags_outdated = true;
        device->tags_generation ++;
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
                                fprintf(f, "S:%s\n", devlink + strlen("/dev/"));

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

        log_debug("created %s file '%s' for '%s'", has_info ? "db" : "empty",
                  path, device->devpath);

        return 0;

fail:
        log_error_errno(r, "failed to create %s file '%s' for '%s'", has_info ? "db" : "empty",
                        path, device->devpath);
        unlink(path);
        unlink(path_tmp);

        return r;
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

int device_read_db_force(sd_device *device) {
        assert(device);

        return device_read_db_aux(device, true);
}
