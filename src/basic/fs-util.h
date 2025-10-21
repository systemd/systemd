/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"
#include "lock-util.h"

/* The following macros add 1 when converting things, since 0 is a valid mode, while the pointer
 * NULL is special */
static inline mode_t PTR_TO_MODE(void *p) {
        return p ? (mode_t) ((uintptr_t) p - 1) : MODE_INVALID;
}
static inline void* MODE_TO_PTR(mode_t m) {
        return m == MODE_INVALID ? NULL : (void *) ((uintptr_t) m + 1);
}

int rmdir_parents(const char *path, const char *stop);

int rename_noreplace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

int readlinkat_malloc(int fd, const char *p, char **ret);
static inline int readlink_malloc(const char *p, char **ret) {
        return readlinkat_malloc(AT_FDCWD, p, ret);
}
int readlink_value(const char *p, char **ret);
int readlink_and_make_absolute(const char *p, char **ret);

int chmod_and_chown_at(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid);
static inline int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        return chmod_and_chown_at(AT_FDCWD, path, mode, uid, gid);
}
int fchmod_and_chown_with_fallback(int fd, const char *path, mode_t mode, uid_t uid, gid_t gid);
static inline int fchmod_and_chown(int fd, mode_t mode, uid_t uid, gid_t gid) {
        return fchmod_and_chown_with_fallback(fd, NULL, mode, uid, gid); /* no fallback */
}

int fchmod_umask(int fd, mode_t mode);
int fchmod_opath(int fd, mode_t m);

int futimens_opath(int fd, const struct timespec ts[2]);

int fd_warn_permissions(const char *path, int fd);
int stat_warn_permissions(const char *path, const struct stat *st);

int access_nofollow(const char *path, int mode);

int touch_fd(int fd, usec_t stamp);
int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid, gid_t gid, mode_t mode);
int touch(const char *path);

int symlinkat_idempotent(const char *target, int atfd, const char *linkpath, bool make_relative);
static inline int symlink_idempotent(const char *target, const char *linkpath, bool make_relative) {
        return symlinkat_idempotent(target, AT_FDCWD, linkpath, make_relative);
}

typedef enum SymlinkFlags {
        SYMLINK_MAKE_RELATIVE = 1 << 0,
        SYMLINK_LABEL         = 1 << 1,
} SymlinkFlags;

int symlinkat_atomic_full(const char *target, int atfd, const char *linkpath, SymlinkFlags flags);
static inline int symlink_atomic(const char *target, const char *linkpath) {
        return symlinkat_atomic_full(target, AT_FDCWD, linkpath, 0);
}

int mknodat_atomic(int atfd, const char *path, mode_t mode, dev_t dev);
static inline int mknod_atomic(const char *path, mode_t mode, dev_t dev) {
        return mknodat_atomic(AT_FDCWD, path, mode, dev);
}

int mkfifoat_atomic(int dir_fd, const char *path, mode_t mode);
static inline int mkfifo_atomic(const char *path, mode_t mode) {
        return mkfifoat_atomic(AT_FDCWD, path, mode);
}

int get_files_in_directory(const char *path, char ***list);

int tmp_dir(const char **ret);
int var_tmp_dir(const char **ret);

int unlink_or_warn(const char *filename);

/* Useful for usage with _cleanup_(), removes a directory and frees the pointer */
char *rmdir_and_free(char *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, rmdir_and_free);

char* unlink_and_free(char *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, unlink_and_free);

int access_fd(int fd, int mode);

typedef enum UnlinkDeallocateFlags {
        UNLINK_REMOVEDIR = 1 << 0,
        UNLINK_ERASE     = 1 << 1,
} UnlinkDeallocateFlags;

int unlinkat_deallocate(int fd, const char *name, UnlinkDeallocateFlags flags);

int open_parent_at(int dir_fd, const char *path, int flags, mode_t mode);
static inline int open_parent(const char *path, int flags, mode_t mode) {
        return open_parent_at(AT_FDCWD, path, flags, mode);
}

int conservative_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
static inline int conservative_rename(const char *oldpath, const char *newpath) {
        return conservative_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

int posix_fallocate_loop(int fd, uint64_t offset, uint64_t size);

int parse_cifs_service(const char *s, char **ret_host, char **ret_service, char **ret_path);

typedef enum XOpenFlags {
        XO_LABEL     = 1 << 0, /* When creating: relabel */
        XO_SUBVOLUME = 1 << 1, /* When creating as directory: make it a subvolume */
        XO_NOCOW     = 1 << 2, /* Enable NOCOW mode after opening */
        XO_REGULAR   = 1 << 3, /* Fail if the inode is not a regular file */
} XOpenFlags;

int open_mkdir_at_full(int dirfd, const char *path, int flags, XOpenFlags xopen_flags, mode_t mode);
static inline int open_mkdir_at(int dirfd, const char *path, int flags, mode_t mode) {
        return open_mkdir_at_full(dirfd, path, flags, 0, mode);
}
static inline int open_mkdir(const char *path, int flags, mode_t mode) {
        return open_mkdir_at_full(AT_FDCWD, path, flags, 0, mode);
}

int openat_report_new(int dirfd, const char *pathname, int flags, mode_t mode, bool *ret_newly_created);

int xopenat_full(int dir_fd, const char *path, int open_flags, XOpenFlags xopen_flags, mode_t mode);
static inline int xopenat(int dir_fd, const char *path, int open_flags) {
        return xopenat_full(dir_fd, path, open_flags, 0, 0);
}

int xopenat_lock_full(int dir_fd, const char *path, int open_flags, XOpenFlags xopen_flags, mode_t mode, LockType locktype, int operation);
static inline int xopenat_lock(int dir_fd, const char *path, int open_flags, LockType locktype, int operation) {
        return xopenat_lock_full(dir_fd, path, open_flags, 0, 0, locktype, operation);
}

int link_fd(int fd, int newdirfd, const char *newpath);

int linkat_replace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

static inline int at_flags_normalize_nofollow(int flags) {
        if (FLAGS_SET(flags, AT_SYMLINK_FOLLOW)) {
                assert(!FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW));
                flags &= ~AT_SYMLINK_FOLLOW;
        } else
                flags |= AT_SYMLINK_NOFOLLOW;
        return flags;
}

static inline int at_flags_normalize_follow(int flags) {
        if (FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW)) {
                assert(!FLAGS_SET(flags, AT_SYMLINK_FOLLOW));
                flags &= ~AT_SYMLINK_NOFOLLOW;
        } else
                flags |= AT_SYMLINK_FOLLOW;
        return flags;
}
