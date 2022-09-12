/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>

typedef enum LabelFixFlags {
        LABEL_IGNORE_ENOENT = 1 << 0,
        LABEL_IGNORE_EROFS  = 1 << 1,
} LabelFixFlags;

int label_fix_full(int atfd, const char *inode_path, const char *label_path, LabelFixFlags flags);

static inline int label_fix(const char *path, LabelFixFlags flags) {
        return label_fix_full(AT_FDCWD, path, path, flags);
}

int symlink_label(const char *old_path, const char *new_path);
int symlink_atomic_full_label(const char *from, const char *to, bool make_relative);
static inline int symlink_atomic_label(const char *from, const char *to) {
        return symlink_atomic_full_label(from, to, false);
}
int mknod_label(const char *pathname, mode_t mode, dev_t dev);

int btrfs_subvol_make_label(const char *path);
