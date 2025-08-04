/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "mkdir.h"

int mkdirat_label(int dirfd, const char *path, mode_t mode);

static inline int mkdir_label(const char *path, mode_t mode) {
        return mkdirat_label(AT_FDCWD, path, mode);
}

int mkdirat_safe_label(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
static inline int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdirat_safe_label(AT_FDCWD, path, mode, uid, gid, flags);
}
int mkdirat_parents_label(int dir_fd, const char *path, mode_t mod);
static inline int mkdir_parents_label(const char *path, mode_t mod) {
        return mkdirat_parents_label(AT_FDCWD, path, mod);
}

int mkdir_parents_safe_label(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);

int mkdir_p_label(const char *path, mode_t mode);
