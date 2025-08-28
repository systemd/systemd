/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum BlockDevListFlags {
        BLOCKDEV_LIST_SHOW_SYMLINKS              = 1 << 0,
        BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING = 1 << 1,
        BLOCKDEV_LIST_IGNORE_ZRAM                = 1 << 2,
        BLOCKDEV_LIST_REQUIRE_LUKS               = 1 << 3,
} BlockDevListFlags;

typedef struct BlockDevice {
        char *node;
        char **symlinks;
        uint64_t diskseq;
} BlockDevice;

#define BLOCK_DEVICE_NULL (BlockDevice) { \
                .diskseq = UINT64_MAX,    \
                .size = UINT64_MAX,       \
        }

void block_device_done(BlockDevice *d);
void block_device_array_free(BlockDevice *d, size_t n_devices);

int blockdev_list(BlockDevListFlags flags, BlockDevice **ret_devices, size_t *ret_n_devices);
