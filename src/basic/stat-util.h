/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>           /* IWYU pragma: export */
#include <sys/statfs.h>         /* IWYU pragma: export */

#include "basic-forward.h"

int stat_verify_regular(const struct stat *st);
int verify_regular_at(int fd, const char *path, bool follow);
int fd_verify_regular(int fd);

int stat_verify_directory(const struct stat *st);
int statx_verify_directory(const struct statx *stx);
int fd_verify_directory(int fd);
int is_dir_at(int fd, const char *path, bool follow);
int is_dir(const char *path, bool follow);

int stat_verify_symlink(const struct stat *st);
int fd_verify_symlink(int fd);
int is_symlink(const char *path);

int stat_verify_linked(const struct stat *st);
int fd_verify_linked(int fd);

int stat_verify_device_node(const struct stat *st);
int is_device_node(const char *path);

int dir_is_empty_at(int dir_fd, const char *path, bool ignore_hidden_or_backup);
static inline int dir_is_empty(const char *path, bool ignore_hidden_or_backup) {
        return dir_is_empty_at(AT_FDCWD, path, ignore_hidden_or_backup);
}

bool stat_may_be_dev_null(struct stat *st) _pure_;
bool stat_is_empty(struct stat *st) _pure_;
static inline bool null_or_empty(struct stat *st) {
        return stat_may_be_dev_null(st) || stat_is_empty(st);
}
int null_or_empty_path_with_root(const char *fn, const char *root);

static inline int null_or_empty_path(const char *fn) {
        return null_or_empty_path_with_root(fn, NULL);
}

int xstatx_full(int fd,
                const char *path,
                int flags,
                unsigned mandatory_mask,
                unsigned optional_mask,
                uint64_t mandatory_attributes,
                struct statx *ret);

static inline int xstatx(
                int fd,
                const char *path,
                int flags,
                unsigned mandatory_mask,
                struct statx *ret) {

        return xstatx_full(fd, path, flags, mandatory_mask, 0, 0, ret);
}

int fd_is_read_only_fs(int fd);
int path_is_read_only_fs(const char *path);

int inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags);
static inline int inode_same(const char *filea, const char *fileb, int flags) {
        return inode_same_at(AT_FDCWD, filea, AT_FDCWD, fileb, flags);
}
static inline int fd_inode_same(int fda, int fdb) {
        return inode_same_at(fda, NULL, fdb, NULL, AT_EMPTY_PATH);
}

/* The .f_type field of struct statfs is really weird defined on
 * different archs. Let's give its type a name. */
typedef typeof_field(struct statfs, f_type) statfs_f_type_t;

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) _pure_;
int is_fs_type_at(int dir_fd, const char *path, statfs_f_type_t magic_value);
static inline int fd_is_fs_type(int fd, statfs_f_type_t magic_value) {
        return is_fs_type_at(fd, NULL, magic_value);
}
static inline int path_is_fs_type(const char *path, statfs_f_type_t magic_value) {
        return is_fs_type_at(AT_FDCWD, path, magic_value);
}

bool is_temporary_fs(const struct statfs *s) _pure_;
bool is_network_fs(const struct statfs *s) _pure_;

int fd_is_temporary_fs(int fd);
int fd_is_network_fs(int fd);

int path_is_temporary_fs(const char *path);
int path_is_network_fs(const char *path);

/* Because statfs.t_type can be int on some architectures, we have to cast
 * the const magic to the type, otherwise the compiler warns about
 * signed/unsigned comparison, because the magic can be 32 bit unsigned.
 */
#define F_TYPE_EQUAL(a, b) (a == (typeof(a)) b)

int proc_mounted(void);

bool stat_inode_same(const struct stat *a, const struct stat *b);
bool stat_inode_unmodified(const struct stat *a, const struct stat *b);

bool statx_inode_same(const struct statx *a, const struct statx *b);
bool statx_mount_same(const struct statx *a, const struct statx *b);

int xstatfsat(int dir_fd, const char *path, struct statfs *ret);

usec_t statx_timestamp_load(const struct statx_timestamp *ts) _pure_;
nsec_t statx_timestamp_load_nsec(const struct statx_timestamp *ts) _pure_;

void inode_hash_func(const struct stat *q, struct siphash *state);
int inode_compare_func(const struct stat *a, const struct stat *b);
extern const struct hash_ops inode_hash_ops;

DECLARE_STRING_TABLE_LOOKUP(inode_type, mode_t);

/* Macros that check whether the stat/statx structures have been initialized already. For "struct stat" we
 * use a check for .st_dev being non-zero, since the kernel unconditionally fills that in, mapping the file
 * to its originating superblock, regardless if the fs is block based or virtual (we also check for .st_mode
 * being MODE_INVALID, since we use that as an invalid marker for separate mode_t fields). For "struct statx"
 * we use the .stx_mask field, which must be non-zero if any of the fields have already been initialized. */
static inline bool stat_is_set(const struct stat *st) {
        return st && st->st_dev != 0 && st->st_mode != MODE_INVALID;
}
static inline bool statx_is_set(const struct statx *sx) {
        return sx && sx->stx_mask != 0;
}

static inline bool inode_type_can_hardlink(mode_t m) {
        /* returns true for all inode types that support hardlinks on linux. Note this is effectively all
         * inode types except for directories (and those weird misc fds such as eventfds() that have no inode
         * type). */
        return IN_SET(m & S_IFMT, S_IFSOCK, S_IFLNK, S_IFREG, S_IFBLK, S_IFCHR, S_IFIFO);
}
