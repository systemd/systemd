/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum BlockDevListFlags {
        BLOCKDEV_LIST_SHOW_SYMLINKS              = 1 << 0, /* Pick up symlinks to block devices too */
        BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING = 1 << 1, /* Only consider block devices with partition scanning */
        BLOCKDEV_LIST_IGNORE_ZRAM                = 1 << 2, /* Ignore ZRAM */
        BLOCKDEV_LIST_REQUIRE_LUKS               = 1 << 3, /* Only consider block devices with LUKS superblocks */
        BLOCKDEV_LIST_IGNORE_ROOT                = 1 << 4, /* Ignore the block device we are currently booted from */
        BLOCKDEV_LIST_IGNORE_EMPTY               = 1 << 5, /* Ignore disks of zero size (usually drives without a medium) */
        BLOCKDEV_LIST_METADATA                   = 1 << 6, /* Fill in model, vendor, subsystem */
} BlockDevListFlags;

typedef struct BlockDevice {
        char *node;
        char **symlinks;
        char *model;
        char *vendor;
        char *subsystem;
        uint64_t diskseq;
        uint64_t size;     /* in bytes */
} BlockDevice;

#define BLOCK_DEVICE_NULL (BlockDevice) { \
                .diskseq = UINT64_MAX,    \
                .size = UINT64_MAX,       \
        }

void block_device_done(BlockDevice *d);
void block_device_array_free(BlockDevice *d, size_t n_devices);

int blockdev_list(BlockDevListFlags flags, BlockDevice **ret_devices, size_t *ret_n_devices);
