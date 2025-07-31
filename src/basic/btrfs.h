/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "forward.h"

int btrfs_validate_subvolume_name(const char *name);

int btrfs_subvol_make(int dir_fd, const char *path);

int btrfs_subvol_make_fallback(int dir_fd, const char *path, mode_t mode);
