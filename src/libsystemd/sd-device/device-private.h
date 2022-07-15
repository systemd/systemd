/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sd-device.h"

#include "macro.h"

int device_new_from_nulstr(sd_device **ret, char *nulstr, size_t len);
int device_new_from_strv(sd_device **ret, char **strv);
int device_new_from_watch_handle_at(sd_device **ret, int dirfd, int wd);
static inline int device_new_from_watch_handle(sd_device **ret, int wd) {
        return device_new_from_watch_handle_at(ret, -1, wd);
}

int device_get_property_bool(sd_device *device, const char *key);
int device_get_device_id(sd_device *device, const char **ret);
int device_get_devlink_priority(sd_device *device, int *ret);
int device_get_watch_handle(sd_device *device);
int device_get_devnode_mode(sd_device *device, mode_t *ret);
int device_get_devnode_uid(sd_device *device, uid_t *ret);
int device_get_devnode_gid(sd_device *device, gid_t *ret);

int device_cache_sysattr_value(sd_device *device, const char *key, char *value);
int device_get_cached_sysattr_value(sd_device *device, const char *key, const char **ret_value);

void device_seal(sd_device *device);
void device_set_is_initialized(sd_device *device);
int device_set_watch_handle(sd_device *device, int wd);
void device_set_db_persist(sd_device *device);
void device_set_devlink_priority(sd_device *device, int priority);
int device_ensure_usec_initialized(sd_device *device, sd_device *device_old);
int device_add_devlink(sd_device *device, const char *devlink);
bool device_has_devlink(sd_device *device, const char *devlink);
int device_add_property(sd_device *device, const char *property, const char *value);
int device_add_propertyf(sd_device *device, const char *key, const char *format, ...) _printf_(3, 4);
int device_add_tag(sd_device *device, const char *tag, bool both);
void device_remove_tag(sd_device *device, const char *tag);
void device_cleanup_tags(sd_device *device);
void device_cleanup_devlinks(sd_device *device);

uint64_t device_get_properties_generation(sd_device *device);
uint64_t device_get_tags_generation(sd_device *device);
uint64_t device_get_devlinks_generation(sd_device *device);

int device_properties_prepare(sd_device *device);
int device_get_properties_nulstr(sd_device *device, const char **ret_nulstr, size_t *ret_len);
int device_get_properties_strv(sd_device *device, char ***ret);

int device_rename(sd_device *device, const char *name);
int device_shallow_clone(sd_device *device, sd_device **ret);
int device_clone_with_db(sd_device *device, sd_device **ret);
int device_copy_properties(sd_device *device_dst, sd_device *device_src);

int device_tag_index(sd_device *dev, sd_device *dev_old, bool add);
int device_update_db(sd_device *device);
int device_delete_db(sd_device *device);
int device_read_db_internal_filename(sd_device *device, const char *filename); /* For fuzzer */
int device_read_db_internal(sd_device *device, bool force);
static inline int device_read_db(sd_device *device) {
        return device_read_db_internal(device, false);
}

int device_read_uevent_file(sd_device *device);

int device_set_action(sd_device *device, sd_device_action_t a);
sd_device_action_t device_action_from_string(const char *s) _pure_;
const char *device_action_to_string(sd_device_action_t a) _const_;
void dump_device_action_table(void);
