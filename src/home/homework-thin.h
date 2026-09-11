/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "forward.h"

typedef struct HomeThinPoolStatus {
        uint64_t transaction_id;
        uint64_t used_metadata, total_metadata;
        uint64_t used_data, total_data;
} HomeThinPoolStatus;

int home_thin_pool_parse_status(const char *status, HomeThinPoolStatus *ret);
int home_thin_pool_validate_table(const char *parameters);
int home_thin_pool_validate(const char *pool_path);
int home_thin_pool_recover(const char *pool_path);

int home_thin_pool_default_size(const char *pool, uint64_t *ret_size, uint64_t *ret_backing_size);
int home_thin_volume_make_path(UserRecord *h, const char *pool, char **ret_path, char **ret_name);
int home_thin_volume_allocate(
                UserRecord *h,
                const char *pool,
                char **ret_pool_uuid,
                uint32_t *ret_device_id);
int home_thin_volume_create(
                UserRecord *h,
                const char *pool,
                uint64_t size,
                sd_id128_t creation_id,
                char **ret_path,
                char **ret_name);
int home_thin_volume_commit(UserRecord *h);
int home_thin_volume_commit_path(UserRecord *h, const char *pool_path);

int home_thin_volume_map_partition(UserRecord *h, int volume_fd, uint64_t offset, uint64_t size, char **ret_path);
int home_thin_volume_activate(UserRecord *h, bool already_active, char **ret_path);
int home_thin_volume_exists(UserRecord *h);
int home_thin_volume_deactivate(UserRecord *h);
int home_thin_volume_deactivate_path(const char *path);
int home_thin_volume_remove(UserRecord *h);
int home_thin_volume_remove_incomplete(UserRecord *h, const char *pool_path);
int home_thin_volume_remove_created(const char *path);
