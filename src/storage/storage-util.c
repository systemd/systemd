/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "json-util.h"
#include "string-table.h"
#include "storage-util.h"

static const char *volume_type_table[_VOLUME_TYPE_MAX] = {
        [VOLUME_BLK] = "blk",
        [VOLUME_REG] = "reg",
        [VOLUME_DIR] = "dir",
};

static const char *create_mode_table[_CREATE_MODE_MAX] = {
        [CREATE_ANY]  = "any",
        [CREATE_NEW]  = "new",
        [CREATE_OPEN] = "open",
};

DEFINE_STRING_TABLE_LOOKUP(volume_type, VolumeType);
DEFINE_STRING_TABLE_LOOKUP(create_mode, CreateMode);

JSON_DISPATCH_ENUM_DEFINE(json_dispatch_volume_type, VolumeType, volume_type_from_string);
JSON_DISPATCH_ENUM_DEFINE(json_dispatch_create_mode, CreateMode, create_mode_from_string);
