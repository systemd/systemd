/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "stat-util.h"

/* Round down to the nearest 4K size. Given that newer hardware generally prefers 4K sectors, let's align our
 * partitions to that too. In the worst case we'll waste 3.5K per partition that way, but I think I can live
 * with that. */
#define DISK_SIZE_ROUND_DOWN(x) ((x) & ~UINT64_C(4095))

/* Rounds up to the nearest 4K boundary. Returns UINT64_MAX on overflow */
#define DISK_SIZE_ROUND_UP(x)                                           \
        ({                                                              \
                uint64_t _x = (x);                                      \
                _x > UINT64_MAX - 4095U ? UINT64_MAX : (_x + 4095U) & ~UINT64_C(4095); \
        })

int resize_fs(int fd, uint64_t sz, uint64_t *ret_size);

#define BTRFS_MINIMAL_SIZE (256U*1024U*1024U)
#define XFS_MINIMAL_SIZE (14U*1024U*1024U)
#define EXT4_MINIMAL_SIZE (1024U*1024U)

uint64_t minimal_size_by_fs_magic(statfs_f_type_t magic);
uint64_t minimal_size_by_fs_name(const char *str);

bool fs_can_online_shrink_and_grow(statfs_f_type_t magic);

int find_smallest_fs_size(const struct statfs *sfs, uint64_t min, uint64_t min_free, uint64_t *ret);
