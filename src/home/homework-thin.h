/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "forward.h"

int home_thin_pool_default_size(const char *pool, uint64_t *ret_size, uint64_t *ret_backing_size);
int home_thin_volume_make_path(UserRecord *h, const char *pool, char **ret_path, char **ret_name);
int home_thin_volume_create(
                UserRecord *h,
                const char *pool,
                uint64_t size,
                sd_id128_t creation_id,
                char **ret_path,
                char **ret_name,
                char **ret_uuid);

int home_thin_volume_map_partition(UserRecord *h, int volume_fd, uint64_t offset, uint64_t size, char **ret_path);
int home_thin_volume_activate(UserRecord *h, bool already_active, char **ret_path);
int home_thin_volume_exists(UserRecord *h);
int home_thin_volume_deactivate(UserRecord *h);
int home_thin_volume_deactivate_path(const char *path);
int home_thin_volume_remove(UserRecord *h);
int home_thin_volume_remove_incomplete(UserRecord *h);
int home_thin_volume_remove_created(const char *path);
