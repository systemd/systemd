/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"

#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "set.h"

struct sd_device {
        unsigned n_ref;

        /* The database version indicates the supported features by the udev database.
         * This is saved and parsed in V field.
         *
         * 0: None of the following features are supported (systemd version <= 246).
         * 1: The current tags (Q) and the database version (V) features are implemented (>= 247).
         */
        unsigned database_version;

        int watch_handle;

        sd_device *parent;

        OrderedHashmap *properties;
        Iterator properties_iterator;
        uint64_t properties_generation; /* changes whenever the properties are changed */
        uint64_t properties_iterator_generation; /* generation when iteration was started */

        /* the subset of the properties that should be written to the db */
        OrderedHashmap *properties_db;

        Hashmap *sysattr_values; /* cached sysattr values */

        Set *sysattrs; /* names of sysattrs */
        Iterator sysattrs_iterator;

        Set *all_tags, *current_tags;
        Iterator all_tags_iterator, current_tags_iterator;
        uint64_t all_tags_iterator_generation, current_tags_iterator_generation; /* generation when iteration was started */
        uint64_t tags_generation; /* changes whenever the tags are changed */

        Set *devlinks;
        Iterator devlinks_iterator;
        uint64_t devlinks_generation; /* changes whenever the devlinks are changed */
        uint64_t devlinks_iterator_generation; /* generation when iteration was started */
        int devlink_priority;

        int ifindex;
        char *devtype;
        char *devname;
        dev_t devnum;

        char **properties_strv; /* the properties hashmap as a strv */
        uint8_t *properties_nulstr; /* the same as a nulstr */
        size_t properties_nulstr_len;

        char *syspath;
        const char *devpath;
        const char *sysnum;
        char *sysname;

        char *subsystem;
        char *driver_subsystem; /* only set for the 'drivers' subsystem */
        char *driver;

        char *device_id;

        usec_t usec_initialized;

        mode_t devmode;
        uid_t devuid;
        gid_t devgid;

        uint64_t diskseq; /* Block device sequence number, monothonically incremented by the kernel on create/attach */

        /* only set when device is passed through netlink */
        sd_device_action_t action;
        uint64_t seqnum;

        bool parent_set:1; /* no need to try to reload parent */
        bool sysattrs_read:1; /* don't try to re-read sysattrs once read */
        bool property_tags_outdated:1; /* need to update TAGS= or CURRENT_TAGS= property */
        bool property_devlinks_outdated:1; /* need to update DEVLINKS= property */
        bool properties_buf_outdated:1; /* need to reread hashmap */
        bool subsystem_set:1; /* don't reread subsystem */
        bool driver_set:1; /* don't reread driver */
        bool uevent_loaded:1; /* don't reread uevent */
        bool db_loaded; /* don't reread db */

        bool is_initialized:1;
        bool sealed:1; /* don't read more information from uevent/db */
        bool db_persist:1; /* don't clean up the db when switching from initrd to real root */
};

#define FOREACH_DEVICE_PROPERTY(device, key, value)                \
        for (key = sd_device_get_property_first(device, &(value)); \
             key;                                                  \
             key = sd_device_get_property_next(device, &(value)))

#define FOREACH_DEVICE_TAG(device, tag)             \
        for (tag = sd_device_get_tag_first(device); \
             tag;                                   \
             tag = sd_device_get_tag_next(device))

#define FOREACH_DEVICE_CURRENT_TAG(device, tag)             \
        for (tag = sd_device_get_current_tag_first(device); \
             tag;                                   \
             tag = sd_device_get_current_tag_next(device))

#define FOREACH_DEVICE_SYSATTR(device, attr)             \
        for (attr = sd_device_get_sysattr_first(device); \
             attr;                                       \
             attr = sd_device_get_sysattr_next(device))

#define FOREACH_DEVICE_DEVLINK(device, devlink)             \
        for (devlink = sd_device_get_devlink_first(device); \
             devlink;                                   \
             devlink = sd_device_get_devlink_next(device))

#define FOREACH_DEVICE(enumerator, device)                               \
        for (device = sd_device_enumerator_get_device_first(enumerator); \
             device;                                                     \
             device = sd_device_enumerator_get_device_next(enumerator))

#define FOREACH_SUBSYSTEM(enumerator, device)                               \
        for (device = sd_device_enumerator_get_subsystem_first(enumerator); \
             device;                                                        \
             device = sd_device_enumerator_get_subsystem_next(enumerator))

#define log_device_full_errno_zerook(device, level, error, ...)         \
        ({                                                              \
                const char *_sysname = NULL;                            \
                sd_device *_d = (device);                               \
                int _level = (level), _e = (error);                     \
                                                                        \
                if (_d && _unlikely_(log_get_max_level() >= LOG_PRI(_level))) \
                        (void) sd_device_get_sysname(_d, &_sysname);    \
                log_object_internal(_level, _e, PROJECT_FILE, __LINE__, __func__, \
                                    _sysname ? "DEVICE=" : NULL, _sysname, \
                                    NULL, NULL, __VA_ARGS__);           \
        })

#define log_device_full_errno(device, level, error, ...)                \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_device_full_errno_zerook(device, level, _error, __VA_ARGS__); \
        })

#define log_device_full(device, level, ...) (void) log_device_full_errno_zerook(device, level, 0, __VA_ARGS__)

#define log_device_debug(device, ...)   log_device_full(device, LOG_DEBUG, __VA_ARGS__)
#define log_device_info(device, ...)    log_device_full(device, LOG_INFO, __VA_ARGS__)
#define log_device_notice(device, ...)  log_device_full(device, LOG_NOTICE, __VA_ARGS__)
#define log_device_warning(device, ...) log_device_full(device, LOG_WARNING, __VA_ARGS__)
#define log_device_error(device, ...)   log_device_full(device, LOG_ERR, __VA_ARGS__)

#define log_device_debug_errno(device, error, ...)   log_device_full_errno(device, LOG_DEBUG, error, __VA_ARGS__)
#define log_device_info_errno(device, error, ...)    log_device_full_errno(device, LOG_INFO, error, __VA_ARGS__)
#define log_device_notice_errno(device, error, ...)  log_device_full_errno(device, LOG_NOTICE, error, __VA_ARGS__)
#define log_device_warning_errno(device, error, ...) log_device_full_errno(device, LOG_WARNING, error, __VA_ARGS__)
#define log_device_error_errno(device, error, ...)   log_device_full_errno(device, LOG_ERR, error, __VA_ARGS__)

int device_new_from_strv(sd_device **ret, char **strv);
int device_new_from_nulstr(sd_device **ret, uint8_t *nulstr, size_t len);
int device_new_from_watch_handle_at(sd_device **ret, int dirfd, int wd);
static inline int device_new_from_watch_handle(sd_device **ret, int wd) {
        return device_new_from_watch_handle_at(ret, -1, wd);
}

#define LATEST_UDEV_DATABASE_VERSION 1

int device_cache_sysattr_value(sd_device *device, const char *key, char *value);
int device_get_cached_sysattr_value(sd_device *device, const char *key, const char **ret_value);

void device_seal(sd_device *device);
void device_set_is_initialized(sd_device *device);
int device_set_watch_handle(sd_device *device, int wd);
void device_set_db_persist(sd_device *device);
void device_set_devlink_priority(sd_device *device, int priority);
int device_ensure_usec_initialized(sd_device *device, sd_device *device_old);

int device_add_property(sd_device *device, const char *property, const char *value);
int device_add_propertyf(sd_device *device, const char *key, const char *format, ...) _printf_(3, 4);
void device_remove_tag(sd_device *device, const char *tag);
void device_cleanup_tags(sd_device *device);
void device_cleanup_devlinks(sd_device *device);

uint64_t device_get_properties_generation(sd_device *device);
uint64_t device_get_tags_generation(sd_device *device);
uint64_t device_get_devlinks_generation(sd_device *device);

int device_properties_prepare(sd_device *device);
int device_get_properties_nulstr(sd_device *device, const uint8_t **nulstr, size_t *len);
int device_get_properties_strv(sd_device *device, char ***strv);

int device_rename(sd_device *device, const char *name);
int device_shallow_clone(sd_device *device, sd_device **ret);
int device_clone_with_db(sd_device *device, sd_device **ret);
int device_copy_properties(sd_device *device_dst, sd_device *device_src);

int device_tag_index(sd_device *dev, sd_device *dev_old, bool add);
int device_update_db(sd_device *device);
int device_delete_db(sd_device *device);

sd_device_action_t device_action_from_string(const char *s) _pure_;
const char *device_action_to_string(sd_device_action_t a) _const_;
void dump_device_action_table(void);

int device_new_aux(sd_device **ret);
int device_add_property_aux(sd_device *device, const char *key, const char *value, bool db);
static inline int device_add_property_internal(sd_device *device, const char *key, const char *value) {
        return device_add_property_aux(device, key, value, false);
}

int device_set_syspath(sd_device *device, const char *_syspath, bool verify);
int device_set_ifindex(sd_device *device, const char *ifindex);
int device_set_devmode(sd_device *device, const char *devmode);
int device_set_devname(sd_device *device, const char *devname);
int device_set_devtype(sd_device *device, const char *devtype);
int device_set_devnum(sd_device *device, const char *major, const char *minor);
int device_set_subsystem(sd_device *device, const char *subsystem);
int device_set_diskseq(sd_device *device, const char *str);
int device_set_drivers_subsystem(sd_device *device);
int device_set_driver(sd_device *device, const char *driver);
int device_set_usec_initialized(sd_device *device, usec_t when);

int device_get_property_bool(sd_device *device, const char *key);
int device_get_devlink_priority(sd_device *device, int *ret);
int device_get_watch_handle(sd_device *device);
int device_get_devnode_mode(sd_device *device, mode_t *ret);
int device_get_devnode_uid(sd_device *device, uid_t *ret);
int device_get_devnode_gid(sd_device *device, gid_t *ret);

int device_get_device_id(sd_device *device, const char **ret);
int device_add_tag(sd_device *device, const char *tag, bool both);
int device_add_devlink(sd_device *device, const char *devlink);
bool device_has_devlink(sd_device *device, const char *devlink);
int device_read_db_internal_filename(sd_device *device, const char *filename); /* For fuzzer */
int device_read_db_internal(sd_device *device, bool force);
static inline int device_read_db(sd_device *device) {
        return device_read_db_internal(device, false);
}

bool device_match_sysattr(sd_device *device, Hashmap *match_sysattr, Hashmap *nomatch_sysattr);
bool device_match_parent(sd_device *device, Set *match_parent, Set *nomatch_parent);

int device_read_uevent_file(sd_device *device);
int device_set_action(sd_device *device, sd_device_action_t a);
