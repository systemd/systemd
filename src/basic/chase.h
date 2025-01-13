/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <stdio.h>

#include "stat-util.h"

typedef enum ChaseFlags {
        CHASE_PREFIX_ROOT        = 1 << 0,  /* The specified path will be prefixed by the specified root before beginning the iteration */
        CHASE_NONEXISTENT        = 1 << 1,  /* It's OK if the path doesn't actually exist. */
        CHASE_NO_AUTOFS          = 1 << 2,  /* Return -EREMOTE if autofs mount point found */
        CHASE_SAFE               = 1 << 3,  /* Return -EPERM if we ever traverse from unprivileged to privileged files or directories */
        CHASE_TRAIL_SLASH        = 1 << 4,  /* Any trailing slash will be preserved */
        CHASE_STEP               = 1 << 5,  /* Just execute a single step of the normalization */
        CHASE_NOFOLLOW           = 1 << 6,  /* Do not follow the path's right-most component. With ret_fd, when the path's
                                             * right-most component refers to symlink, return O_PATH fd of the symlink. */
        CHASE_WARN               = 1 << 7,  /* Emit an appropriate warning when an error is encountered.
                                             * Note: this may do an NSS lookup, hence this flag cannot be used in PID 1. */
        CHASE_AT_RESOLVE_IN_ROOT = 1 << 8,  /* Same as openat2()'s RESOLVE_IN_ROOT flag, symlinks are resolved
                                             * relative to the given directory fd instead of root. */
        CHASE_PROHIBIT_SYMLINKS  = 1 << 9,  /* Refuse all symlinks */
        CHASE_PARENT             = 1 << 10, /* Chase the parent directory of the given path. Note that the
                                             * full path is still stored in ret_path and only the returned
                                             * file descriptor will point to the parent directory. Note that
                                             * the result path is the root or '.', then the file descriptor
                                             * also points to the result path even if this flag is set.
                                             * When this specified, chase() will succeed with 1 even if the
                                             * file points to the last path component does not exist. */
        CHASE_MKDIR_0755         = 1 << 11, /* Create any missing directories in the given path. */
        CHASE_EXTRACT_FILENAME   = 1 << 12, /* Only return the last component of the resolved path */
        CHASE_MUST_BE_DIRECTORY  = 1 << 13, /* Fail if returned inode fd is not a dir */
        CHASE_MUST_BE_REGULAR    = 1 << 14, /* Fail if returned inode fd is not a regular file */
} ChaseFlags;

bool unsafe_transition(const struct stat *a, const struct stat *b);

/* How many iterations to execute before returning -ELOOP */
#define CHASE_MAX 32

int chase(const char *path_with_prefix, const char *root, ChaseFlags chase_flags, char **ret_path, int *ret_fd);

int chaseat_prefix_root(const char *path, const char *root, char **ret);
int chase_extract_filename(const char *path, const char *root, char **ret);

int chase_and_open(const char *path, const char *root, ChaseFlags chase_flags, int open_flags, char **ret_path);
int chase_and_opendir(const char *path, const char *root, ChaseFlags chase_flags, char **ret_path, DIR **ret_dir);
int chase_and_stat(const char *path, const char *root, ChaseFlags chase_flags, char **ret_path, struct stat *ret_stat);
int chase_and_access(const char *path, const char *root, ChaseFlags chase_flags, int access_mode, char **ret_path);
int chase_and_fopen_unlocked(const char *path, const char *root, ChaseFlags chase_flags, const char *open_flags, char **ret_path, FILE **ret_file);
int chase_and_unlink(const char *path, const char *root, ChaseFlags chase_flags, int unlink_flags, char **ret_path);
int chase_and_open_parent(const char *path, const char *root, ChaseFlags chase_flags, char **ret_filename);

int chaseat(int dir_fd, const char *path, ChaseFlags flags, char **ret_path, int *ret_fd);

int chase_and_openat(int dir_fd, const char *path, ChaseFlags chase_flags, int open_flags, char **ret_path);
int chase_and_opendirat(int dir_fd, const char *path, ChaseFlags chase_flags, char **ret_path, DIR **ret_dir);
int chase_and_statat(int dir_fd, const char *path, ChaseFlags chase_flags, char **ret_path, struct stat *ret_stat);
int chase_and_accessat(int dir_fd, const char *path, ChaseFlags chase_flags, int access_mode, char **ret_path);
int chase_and_fopenat_unlocked(int dir_fd, const char *path, ChaseFlags chase_flags, const char *open_flags, char **ret_path, FILE **ret_file);
int chase_and_unlinkat(int dir_fd, const char *path, ChaseFlags chase_flags, int unlink_flags, char **ret_path);
int chase_and_open_parent_at(int dir_fd, const char *path, ChaseFlags chase_flags, char **ret_filename);
