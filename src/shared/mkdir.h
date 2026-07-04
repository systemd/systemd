/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#include "../basic/mkdir.h"      /* IWYU pragma: export */

int mkdirat_label(int dirfd, const char *path, mode_t mode, LabelContext *label_context);

static inline int mkdir_label(const char *path, mode_t mode) {
        return mkdirat_label(AT_FDCWD, path, mode, /* label_context= */ NULL);
}

int mkdirat_safe_label(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, LabelContext *label_context);
static inline int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdirat_safe_label(AT_FDCWD, path, mode, uid, gid, flags, /* label_context= */ NULL);
}
int mkdirat_parents_label(int dir_fd, const char *path, mode_t mod, LabelContext *label_context);
static inline int mkdir_parents_label(const char *path, mode_t mod) {
        return mkdirat_parents_label(AT_FDCWD, path, mod, /* label_context= */ NULL);
}

static inline int mkdir_parents_safe_label(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_parents_internal(prefix, path, mode, uid, gid, flags, mkdirat_label, /* label_context= */ NULL);
}

static inline int mkdir_p_label(const char *path, mode_t mode) {
        return mkdir_p_internal(/* prefix= */ NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_label, /* label_context= */ NULL);
}
