/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#include "../basic/mkdir.h"      /* IWYU pragma: export */

int mkdirat_label(int dirfd, const char *path, mode_t mode, void *label_userdata);

static inline int mkdir_label(const char *path, mode_t mode) {
        return mkdirat_label(AT_FDCWD, path, mode, NULL);
}

int mkdirat_safe_label(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, void *label_userdata);
static inline int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdirat_safe_label(AT_FDCWD, path, mode, uid, gid, flags, NULL);
}
int mkdirat_parents_label(int dir_fd, const char *path, mode_t mod, void *label_userdata);
static inline int mkdir_parents_label(const char *path, mode_t mod) {
        return mkdirat_parents_label(AT_FDCWD, path, mod, NULL);
}

static inline int mkdir_parents_safe_label(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_parents_internal(prefix, path, mode, uid, gid, flags, mkdirat_label, NULL);
}

static inline int mkdir_p_label(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_label, NULL);
}
