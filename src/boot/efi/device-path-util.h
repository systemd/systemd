/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "proto/device-path.h"

EFI_STATUS make_file_device_path(EFI_HANDLE device, const char16_t *file, EFI_DEVICE_PATH **ret_dp);
EFI_STATUS device_path_to_str(const EFI_DEVICE_PATH *dp, char16_t **ret);
bool device_path_startswith(const EFI_DEVICE_PATH *dp, const EFI_DEVICE_PATH *start);
EFI_DEVICE_PATH *device_path_replace_node(
                const EFI_DEVICE_PATH *path, const EFI_DEVICE_PATH *node, const EFI_DEVICE_PATH *new_node);

static inline EFI_DEVICE_PATH *device_path_next_node(const EFI_DEVICE_PATH *dp) {
        assert(dp);
        return (EFI_DEVICE_PATH *) ((uint8_t *) dp + dp->Length);
}

static inline bool device_path_is_end(const EFI_DEVICE_PATH *dp) {
        assert(dp);
        return dp->Type == END_DEVICE_PATH_TYPE && dp->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE;
}

#define DEVICE_PATH_END_NODE                               \
        (EFI_DEVICE_PATH) {                                \
                .Type = END_DEVICE_PATH_TYPE,              \
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE, \
                .Length = sizeof(EFI_DEVICE_PATH)          \
        }
