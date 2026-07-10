/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum MkdirFlags {
        MKDIR_FOLLOW_SYMLINK  = 1 << 0,
        MKDIR_IGNORE_EXISTING = 1 << 1,  /* Quietly accept a preexisting directory (or file) */
        MKDIR_WARN_MODE       = 1 << 2,  /* Log at LOG_WARNING when mode doesn't match */
} MkdirFlags;

int mkdirat_errno_wrapper(int dirfd, const char *pathname, mode_t mode);

int mkdirat_safe(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
static inline int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdirat_safe(AT_FDCWD, path, mode, uid, gid, flags);
}
int mkdirat_parents(int dir_fd, const char *path, mode_t mode);
static inline int mkdir_parents(const char *path, mode_t mode) {
        return mkdirat_parents(AT_FDCWD, path, mode);
}
int mkdir_parents_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
int mkdir_p(const char *path, mode_t mode);
int mkdir_p_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags);
int mkdir_p_root_full(const char *root, const char *p, uid_t uid, gid_t gid, mode_t m, usec_t ts, Hashmap *subvolumes);
static inline int mkdir_p_root(const char *root, const char *p, uid_t uid, gid_t gid, mode_t m) {
        return mkdir_p_root_full(root, p, uid, gid, m, USEC_INFINITY, NULL);
}

/* The following are used to implement the mkdir_xyz_label() calls, don't use otherwise. */
typedef int (*mkdirat_func_t)(int dir_fd, const char *pathname, mode_t mode);
int mkdirat_safe_internal(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdir);
static inline int mkdir_safe_internal(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdir) {
        return mkdirat_safe_internal(AT_FDCWD, path, mode, uid, gid, flags, _mkdir);
}
int mkdirat_parents_internal(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdirat);
int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdir);
int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdir);
