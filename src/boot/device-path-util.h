/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "proto/device-path.h"

EFI_STATUS make_file_device_path(EFI_HANDLE device, const char16_t *file, EFI_DEVICE_PATH **ret_dp);
EFI_STATUS make_url_device_path(const char16_t *url, EFI_DEVICE_PATH **ret);
EFI_STATUS device_path_to_str(const EFI_DEVICE_PATH *dp, char16_t **ret);
bool device_path_startswith(const EFI_DEVICE_PATH *dp, const EFI_DEVICE_PATH *start);
EFI_DEVICE_PATH *device_path_replace_node(
                const EFI_DEVICE_PATH *path, const EFI_DEVICE_PATH *node, const EFI_DEVICE_PATH *new_node);

static inline EFI_DEVICE_PATH *device_path_next_node(const EFI_DEVICE_PATH *dp) {
        assert(dp);
        /* The node Length includes the 4-byte header, so a well-formed node is at least that long. Paths
         * coming from untrusted sources must be checked with device_path_is_valid() before being walked. */
        assert(dp->Length >= sizeof(EFI_DEVICE_PATH));
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

size_t device_path_size(const EFI_DEVICE_PATH *dp);

/* Validates that a device path is well-formed and fully contained within the given size, terminated by an
 * end node. Use on paths from untrusted sources (e.g. EFI variables) before walking them. */
bool device_path_is_valid(const EFI_DEVICE_PATH *dp, size_t size);

EFI_DEVICE_PATH *device_path_dup(const EFI_DEVICE_PATH *dp);
