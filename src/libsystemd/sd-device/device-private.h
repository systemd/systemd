/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h" /* IWYU pragma: export */

#include "sd-forward.h"

int device_new_from_mode_and_devnum(sd_device **ret, mode_t mode, dev_t devnum);
int device_new_from_nulstr(sd_device **ret, char *nulstr, size_t len);
int device_new_from_strv(sd_device **ret, char **strv);

int device_opendir(sd_device *device, const char *subdir, DIR **ret);

int device_get_sysnum_unsigned(sd_device *device, unsigned *ret);
int device_get_property_bool(sd_device *device, const char *key);
int device_get_property_int(sd_device *device, const char *key, int *ret);
int device_get_property_uint(sd_device *device, const char *key, unsigned *ret);
int device_get_ifname(sd_device *device, const char **ret);
int device_get_sysattr_int(sd_device *device, const char *sysattr, int *ret_value);
int device_get_sysattr_unsigned_full(sd_device *device, const char *sysattr, unsigned base, unsigned *ret_value);
static inline int device_get_sysattr_unsigned(sd_device *device, const char *sysattr, unsigned *ret_value) {
        return device_get_sysattr_unsigned_full(device, sysattr, 0, ret_value);
}
int device_get_sysattr_u32(sd_device *device, const char *sysattr, uint32_t *ret_value);
int device_get_sysattr_u64(sd_device *device, const char *sysattr, uint64_t *ret_value);
int device_get_sysattr_bool(sd_device *device, const char *sysattr);
int device_get_devlink_priority(sd_device *device, int *ret);
int device_get_devnode_mode(sd_device *device, mode_t *ret);
int device_get_devnode_uid(sd_device *device, uid_t *ret);
int device_get_devnode_gid(sd_device *device, gid_t *ret);

int device_chase(sd_device *device, const char *path, ChaseFlags flags, char **ret_resolved, int *ret_fd);
void device_clear_sysattr_cache(sd_device *device);
int device_cache_sysattr_value(sd_device *device, char *key, char *value, int error);

void device_seal(sd_device *device);
void device_set_is_initialized(sd_device *device);
void device_set_db_persist(sd_device *device);
void device_set_devlink_priority(sd_device *device, int priority);
int device_ensure_usec_initialized(sd_device *device, sd_device *device_old);
int device_add_devlink(sd_device *device, const char *devlink);
int device_remove_devlink(sd_device *device, const char *devlink);
bool device_has_devlink(sd_device *device, const char *devlink);
int device_add_property(sd_device *device, const char *key, const char *value);
int device_add_propertyf(sd_device *device, const char *key, const char *format, ...) _printf_(3, 4);
int device_add_tag(sd_device *device, const char *tag, bool both);
void device_remove_tag(sd_device *device, const char *tag);
int device_copy_all_tags(sd_device *dest, sd_device *src);
int device_cleanup_tags(sd_device *device, sd_device *original);
void device_cleanup_devlinks(sd_device *device);

uint64_t device_get_properties_generation(sd_device *device);
uint64_t device_get_tags_generation(sd_device *device);
uint64_t device_get_devlinks_generation(sd_device *device);

int device_properties_prepare(sd_device *device);
int device_get_properties_nulstr(sd_device *device, const char **ret_nulstr, size_t *ret_len);
int device_get_properties_strv(sd_device *device, char ***ret);

int device_clone_with_db(sd_device *device, sd_device **ret);

int device_tag_index(sd_device *device, bool add);
bool device_should_have_db(sd_device *device);
int device_has_db(sd_device *device);
int device_update_db(sd_device *device);
int device_delete_db(sd_device *device);
int device_read_db_internal_filename(sd_device *device, const char *filename); /* For fuzzer */
int device_read_db_internal(sd_device *device, bool force);
static inline int device_read_db(sd_device *device) {
        return device_read_db_internal(device, false);
}

int device_read_uevent_file(sd_device *device);

int device_set_action(sd_device *device, sd_device_action_t a);
DECLARE_STRING_TABLE_LOOKUP(device_action, sd_device_action_t);
