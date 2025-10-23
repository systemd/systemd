/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

typedef enum BtrfsSubvolFlags {
        BTRFS_SUBVOL_RO               = 1 << 0,
        BTRFS_SUBVOL_NODATACOW        = 1 << 1,
        _BTRFS_SUBVOL_FLAGS_MASK      = BTRFS_SUBVOL_NODATACOW|BTRFS_SUBVOL_RO,
        _BTRFS_SUBVOL_FLAGS_INVALID   = -EINVAL,
        _BTRFS_SUBVOL_FLAGS_ERRNO_MAX = -ERRNO_MAX, /* Ensure the whole errno range fits into this enum */
} BtrfsSubvolFlags;

int btrfs_validate_subvolume_name(const char *name);

int btrfs_subvol_make(int dir_fd, const char *path);

int btrfs_subvol_make_fallback(int dir_fd, const char *path, mode_t mode);

int btrfs_subvol_set_nodatacow_at(int dir_fd, const char *path, bool b);
static inline int btrfs_subvol_set_nodatacow_fd(int fd, bool b) {
        return btrfs_subvol_set_nodatacow_at(fd, NULL, b);
}
static inline int btrfs_subvol_set_nodatacow(const char *path, bool b) {
        return btrfs_subvol_set_nodatacow_at(AT_FDCWD, path, b);
}

int btrfs_subvol_get_nodatacow_fd(int fd);
