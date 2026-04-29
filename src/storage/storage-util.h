/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "string-table-fundamental.h"
#include "string-util.h"

/* This closely follows the kernel's inode type naming, i.e. is supposed to be a subset of what
 * inode_type_from_string() parses. */
typedef enum VolumeType {
        VOLUME_BLK,
        VOLUME_REG,
        VOLUME_DIR,
        _VOLUME_TYPE_MAX,
        _VOLUME_TYPE_INVALID = -EINVAL,
} VolumeType;

typedef enum CreateMode {
        CREATE_ANY,
        CREATE_NEW,
        CREATE_OPEN,
        _CREATE_MODE_MAX,
        _CREATE_MODE_INVALID = -EINVAL,
} CreateMode;

DECLARE_STRING_TABLE_LOOKUP(volume_type, VolumeType);
DECLARE_STRING_TABLE_LOOKUP(create_mode, CreateMode);

int json_dispatch_volume_type(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_create_mode(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

static inline bool storage_volume_name_is_valid(const char *n) {
        return string_is_safe(n, /* flags= */ 0);
}

static inline bool storage_template_name_is_valid(const char *n) {
        return string_is_safe(n, /* flags= */ 0);
}

static inline bool storage_provider_name_is_valid(const char *n) {
        return string_is_safe(n, STRING_FILENAME);
}
