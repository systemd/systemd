/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "stat-util.h"

int resize_fs(int fd, uint64_t sz, uint64_t *ret_size);

#define BTRFS_MINIMAL_SIZE (256U*U64_MB)
#define XFS_MINIMAL_SIZE (300U*U64_MB)
#define EXT4_MINIMAL_SIZE (32U*U64_MB)

uint64_t minimal_size_by_fs_magic(statfs_f_type_t magic);
uint64_t minimal_size_by_fs_name(const char *str);

bool fs_can_online_shrink_and_grow(statfs_f_type_t magic);
