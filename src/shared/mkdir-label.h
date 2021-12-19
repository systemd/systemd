/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <sys/types.h>

#include "mkdir.h"

int mkdirat_label(int dirfd, const char *path, mode_t mode);

static inline int mkdir_label(const char *path, mode_t mode) {
        return mkdirat_label(AT_FDCWD, path, mode);
}

int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
int mkdir_parents_label(const char *path, mode_t mod);
int mkdir_p_label(const char *path, mode_t mode);
