/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

typedef enum MkdirFlags {
        MKDIR_FOLLOW_SYMLINK  = 1 << 0,
        MKDIR_IGNORE_EXISTING = 1 << 1,  /* Quietly accept a preexisting directory (or file) */
        MKDIR_WARN_MODE       = 1 << 2,  /* Log at LOG_WARNING when mode doesn't match */
} MkdirFlags;

int mkdirat_errno_wrapper(int dirfd, const char *pathname, mode_t mode);

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
int mkdir_parents(const char *path, mode_t mode);
int mkdir_parents_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
int mkdir_p(const char *path, mode_t mode);
int mkdir_p_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
int mkdir_p_root(const char *root, const char *p, uid_t uid, gid_t gid, mode_t m);

/* The following are used to implement the mkdir_xyz_label() calls, don't use otherwise. */
typedef int (*mkdirat_func_t)(int dir_fd, const char *pathname, mode_t mode);
int mkdir_safe_internal(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdir);
int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdir);
int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdir);
