/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#include "../basic/label-util.h"      /* IWYU pragma: export */

typedef enum LabelFixFlags {
        LABEL_IGNORE_ENOENT = 1 << 0,
        LABEL_IGNORE_EROFS  = 1 << 1,
} LabelFixFlags;

int label_fix_full(int atfd, const char *inode_path, const char *label_path, LabelFixFlags flags, LabelContext *label_context);

static inline int label_fix(const char *path, LabelFixFlags flags) {
        return label_fix_full(AT_FDCWD, path, path, flags, /* label_context= */ NULL);
}

int symlink_label(const char *old_path, const char *new_path, LabelContext *label_context);

int mknodat_label(int dirfd, const char *pathname, mode_t mode, dev_t dev, LabelContext *label_context);
static inline int mknod_label(const char *pathname, mode_t mode, dev_t dev) {
        return mknodat_label(AT_FDCWD, pathname, mode, dev, /* label_context= */ NULL);
}

int btrfs_subvol_make_label(const char *path, LabelContext *label_context);

int mac_init(void);
int mac_init_lazy(void);

int mac_label_context_new(const char *root, LabelContext **ret);
LabelContext* mac_label_context_free(LabelContext *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(LabelContext*, mac_label_context_free);
