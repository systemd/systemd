/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sd-device.h"

int device_new_from_nulstr(sd_device **ret, uint8_t *nulstr, size_t len);
int device_new_from_strv(sd_device **ret, char **strv);
int device_new_from_stat_rdev(sd_device **ret, const struct stat *st);

int device_get_id_filename(sd_device *device, const char **ret);

int device_get_devlink_priority(sd_device *device, int *priority);
int device_get_watch_handle(sd_device *device, int *handle);
int device_get_devnode_mode(sd_device *device, mode_t *mode);
int device_get_devnode_uid(sd_device *device, uid_t *uid);
int device_get_devnode_gid(sd_device *device, gid_t *gid);

void device_seal(sd_device *device);
void device_set_is_initialized(sd_device *device);
void device_set_watch_handle(sd_device *device, int fd);
void device_set_db_persist(sd_device *device);
void device_set_devlink_priority(sd_device *device, int priority);
int device_ensure_usec_initialized(sd_device *device, sd_device *device_old);
int device_add_devlink(sd_device *device, const char *devlink);
int device_add_property(sd_device *device, const char *property, const char *value);
int device_add_tag(sd_device *device, const char *tag);
void device_remove_tag(sd_device *device, const char *tag);
void device_cleanup_tags(sd_device *device);
void device_cleanup_devlinks(sd_device *device);

uint64_t device_get_properties_generation(sd_device *device);
uint64_t device_get_tags_generation(sd_device *device);
uint64_t device_get_devlinks_generation(sd_device *device);

int device_get_properties_nulstr(sd_device *device, const uint8_t **nulstr, size_t *len);
int device_get_properties_strv(sd_device *device, char ***strv);

int device_rename(sd_device *device, const char *name);
int device_shallow_clone(sd_device *old_device, sd_device **new_device);
int device_clone_with_db(sd_device *old_device, sd_device **new_device);
int device_copy_properties(sd_device *device_dst, sd_device *device_src);
int device_new_from_synthetic_event(sd_device **new_device, const char *syspath, const char *action);

int device_tag_index(sd_device *dev, sd_device *dev_old, bool add);
int device_update_db(sd_device *device);
int device_delete_db(sd_device *device);
int device_read_db_force(sd_device *device);
