/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum BlockDevListFlags {
        BLOCKDEV_LIST_SHOW_SYMLINKS              = 1 << 0,
        BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING = 1 << 1,
        BLOCKDEV_LIST_IGNORE_ZRAM                = 1 << 2,
        BLOCKDEV_LIST_REQUIRE_LUKS               = 1 << 3,
} BlockDevListFlags;

int blockdev_list(BlockDevListFlags flags);
