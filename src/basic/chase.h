/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum ChaseFlags {
        CHASE_PREFIX_ROOT        = 1 << 0,  /* The specified path will be prefixed by the specified root before beginning the iteration */
        CHASE_NONEXISTENT        = 1 << 1,  /* It's OK if the path doesn't actually exist. */
        CHASE_NO_AUTOFS          = 1 << 2,  /* Return -EREMOTE if autofs mount point found */
        CHASE_TRIGGER_AUTOFS     = 1 << 3,  /* Use open_tree() rather than openat() to trigger autofs mount */
        CHASE_SAFE               = 1 << 4,  /* Return -ENOLINK if we ever traverse from unprivileged to privileged files or directories */
        CHASE_TRAIL_SLASH        = 1 << 5,  /* Any trailing slash will be preserved */
        CHASE_STEP               = 1 << 6,  /* Just execute a single step of the normalization */
        CHASE_NOFOLLOW           = 1 << 7,  /* Do not follow the path's right-most component. With ret_fd, when the path's
                                             * right-most component refers to symlink, return O_PATH fd of the symlink. */
        CHASE_WARN               = 1 << 8,  /* Emit an appropriate warning when an error is encountered.
                                             * Note: this may do an NSS lookup, hence this flag cannot be used in PID 1. */
        CHASE_PROHIBIT_SYMLINKS  = 1 << 9,  /* Refuse all symlinks */
        CHASE_PARENT             = 1 << 10, /* Chase the parent directory of the given path. Note that the
                                             * full path is still stored in ret_path and only the returned
                                             * file descriptor will point to the parent directory. Note that
                                             * if the result path is the root, '.', or ends with '..', the
                                             * file descriptor points to the result itself. With
                                             * CHASE_EXTRACT_FILENAME_HARDER, the filename is '.' in that case.
                                             * When this specified, chase() will succeed with 1 even if the
                                             * file points to the last path component does not exist. */
        CHASE_MKDIR_0755         = 1 << 11, /* Create any missing directories in the given path. */
        CHASE_EXTRACT_FILENAME   = 1 << 12, /* Extract a filename that passes filename_is_valid(), or fail. */
        CHASE_MUST_BE_DIRECTORY  = 1 << 13, /* Fail if returned inode fd is not a dir */
        CHASE_MUST_BE_REGULAR    = 1 << 14, /* Fail if returned inode fd is not a regular file */
        CHASE_MUST_BE_SOCKET     = 1 << 15, /* Fail if returned inode fd is not a socket */
        CHASE_MAX_MODE           = 1 << 16, /* Return -ENOLINK if a directory on the way, the starting one
                                             * and the root included, has permission bits beyond 0775, or
                                             * the final regular file any bit beyond 0664, suid/sgid/sticky
                                             * included. Symlinks are never checked. */
        CHASE_NO_SYNC            = 1 << 17, /* Don't synchronize attributes with the server on network file systems,
                                             * so that we don't block if it is unreachable. Attributes may hence be
                                             * stale, which also applies to the st_uid and st_mode that CHASE_SAFE
                                             * and CHASE_MAX_MODE check. Doesn't apply to the final fstat*() of
                                             * chase_and_stat*(). Keep this in mind */
        CHASE_EXTRACT_FILENAME_HARDER = CHASE_EXTRACT_FILENAME | (1 << 18), /* Return "." if there is no filename. */
        CHASE_EMPTY_PATH         = 1 << 19, /* An empty path refers to the inode of dir_fd itself. */
} ChaseFlags;

int statx_unsafe_transition(const struct statx *a, const struct statx *b);
bool stat_unsafe_transition(const struct stat *a, const struct stat *b);

/* How many iterations to execute before returning -ELOOP */
#define CHASE_MAX 128U

int chase(const char *path_with_prefix, const char *root, ChaseFlags flags, char **ret_path, int *ret_fd);

/* Relative chaseat() output needs the path of its starting directory as the prefix. */
int chaseat_make_absolute(const char *path, const char *base, char **ret);
int chase_split_prefix_filename(const char *path, const char *root, char **ret_dir, char **ret_filename);

/* chase_xopenat() wraps xopenat_full() and translates CHASE_NOFOLLOW, CHASE_MUST_BE_*, and
 * CHASE_TRIGGER_AUTOFS into open and xopen flags. Callers must validate other chase flags while
 * resolving the path. */
int chase_xopenat(int dir_fd, const char *path, ChaseFlags chase_flags, int open_flags, XOpenFlags xopen_flags);

int chase_and_open(const char *path, const char *root, ChaseFlags chase_flags, int open_flags, char **ret_path);
int chase_and_opendir(const char *path, const char *root, ChaseFlags chase_flags, char **ret_path, DIR **ret_dir);
int chase_and_stat(const char *path, const char *root, ChaseFlags chase_flags, char **ret_path, struct stat *ret_stat);
int chase_and_access(const char *path, const char *root, ChaseFlags chase_flags, int access_mode, char **ret_path);
int chase_and_fopen_unlocked(const char *path, const char *root, ChaseFlags chase_flags, const char *open_flags, char **ret_path, FILE **ret_file);
int chase_and_unlink(const char *path, const char *root, ChaseFlags chase_flags, int unlink_flags, char **ret_path);
int chase_and_open_parent(const char *path, const char *root, ChaseFlags chase_flags, char **ret_filename);

/* CHASE_EMPTY_PATH makes an empty path refer to dir_fd itself, including a file or symlink. */
int chaseat(int root_fd, int dir_fd, const char *path, ChaseFlags flags, char **ret_path, int *ret_fd);

int chase_and_openat(int root_fd, int dir_fd, const char *path, ChaseFlags chase_flags, int open_flags, char **ret_path);
int chase_and_opendirat(int root_fd, int dir_fd, const char *path, ChaseFlags chase_flags, char **ret_path, DIR **ret_dir);
int chase_and_statat(int root_fd, int dir_fd, const char *path, ChaseFlags chase_flags, char **ret_path, struct stat *ret_stat);
int chase_and_accessat(int root_fd, int dir_fd, const char *path, ChaseFlags chase_flags, int access_mode, char **ret_path);
int chase_and_fopenat_unlocked(int root_fd, int dir_fd, const char *path, ChaseFlags chase_flags, const char *open_flags, char **ret_path, FILE **ret_file);
int chase_and_unlinkat(int root_fd, int dir_fd, const char *path, ChaseFlags chase_flags, int unlink_flags, char **ret_path);
int chase_and_open_parent_at(int root_fd, int dir_fd, const char *path, ChaseFlags chase_flags, char **ret_filename);
