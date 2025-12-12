/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "machine-forward.h"

typedef enum ImageCleanPoolMode {
        IMAGE_CLEAN_POOL_REMOVE_ALL,
        IMAGE_CLEAN_POOL_REMOVE_HIDDEN,
        _IMAGE_CLEAN_POOL_MAX,
        _IMAGE_CLEAN_POOL_INVALID = -EINVAL,
} ImageCleanPoolMode;

ImageCleanPoolMode image_clean_pool_mode_from_string(const char *s) _pure_;
const char* image_clean_pool_mode_to_string(ImageCleanPoolMode mode) _const_;

int image_clean_pool_operation(Manager *manager, ImageCleanPoolMode mode, Operation **ret_operation);
int clean_pool_read_first_entry(FILE *file, int child_error, sd_bus_error *error);
int clean_pool_read_next_entry(FILE *file, char **ret_name, uint64_t *ret_usage);
