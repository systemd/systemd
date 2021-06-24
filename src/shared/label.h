/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

typedef enum LabelFixFlags {
        LABEL_IGNORE_ENOENT = 1 << 0,
        LABEL_IGNORE_EROFS  = 1 << 1,
} LabelFixFlags;

int label_fix_container(const char *path, const char *inside_path, LabelFixFlags flags);
static inline int label_fix(const char *path, LabelFixFlags flags) {
        return label_fix_container(path, path, flags);
}

int mkdir_label(const char *path, mode_t mode);
int mkdirat_label(int dirfd, const char *path, mode_t mode);
int symlink_label(const char *old_path, const char *new_path);
int symlink_atomic_label(const char *from, const char *to);
int mknod_label(const char *pathname, mode_t mode, dev_t dev);

int btrfs_subvol_make_label(const char *path);
