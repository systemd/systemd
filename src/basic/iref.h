/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum IRefFlags {
        IREF_RDONLY            = 0,
        IREF_WRONLY            = 1ULL << 0,
        IREF_RDWR              = 1ULL << 1,
        IREF_PATH              = 1ULL << 2,
        IREF_DIRECTORY         = 1ULL << 3,
        IREF_REGULAR           = 1ULL << 4,
        IREF_SOCKET            = 1ULL << 5,
        IREF_NOFOLLOW          = 1ULL << 6,
        IREF_CREAT             = 1ULL << 7,
        IREF_EXCL              = 1ULL << 8,
        IREF_TRUNC             = 1ULL << 9,
        IREF_APPEND            = 1ULL << 10,
        IREF_NONBLOCK          = 1ULL << 11,
        IREF_NOCTTY            = 1ULL << 12,
        IREF_DSYNC             = 1ULL << 13,
        IREF_SYNC              = 1ULL << 14,
        IREF_DIRECT            = 1ULL << 15,
        IREF_NOATIME           = 1ULL << 16,
        IREF_ASYNC             = 1ULL << 17,
        IREF_TMPFILE           = 1ULL << 18,
        IREF_NONEXISTENT       = 1ULL << 19,
        IREF_NO_AUTOFS         = 1ULL << 20,
        IREF_TRIGGER_AUTOFS    = 1ULL << 21,
        IREF_SAFE              = 1ULL << 22,
        IREF_STEP              = 1ULL << 23,
        IREF_WARN              = 1ULL << 24,
        IREF_PROHIBIT_SYMLINKS = 1ULL << 25,
        IREF_PARENT            = 1ULL << 26,
        IREF_MKDIR_0755        = 1ULL << 27,
        IREF_EXTRACT_FILENAME  = 1ULL << 28,
        IREF_MAX_MODE          = 1ULL << 29,
        IREF_NO_SYNC           = 1ULL << 30,
        IREF_LABEL             = 1ULL << 31,
        IREF_SUBVOLUME         = 1ULL << 32,
        IREF_NOCOW             = 1ULL << 33,
        IREF_COW               = 1ULL << 34,
        IREF_AUTO_RW_RO        = 1ULL << 35,
        IREF_EXTRACT_FILENAME_HARDER = IREF_EXTRACT_FILENAME | (1ULL << 36),
} IRefFlags;

/* Symlinks and ".." in paths resolved through an IRef can't leave its root directory.
 * iref_fd(), iref_chase(), iref_open_parent(), iref_open_full(), iref_open(), and iref_fopen_unlocked()
 * accept a NULL IRef to use the host root directory. */

DECLARE_TRIVIAL_REF_UNREF_FUNC(IRef, iref);
DEFINE_TRIVIAL_CLEANUP_FUNC(IRef*, iref_unref);

/* iref_open_root() resolves relative paths from the host root directory. flags may be 0 to obtain a
 * readable directory fd instead of an O_PATH fd. */
int iref_open_root(const char *path, IRefFlags flags, IRef **ret);

/* iref_fd(NULL) returns XAT_FDROOT for APIs that take a root fd. */
int iref_fd(const IRef *i);
int iref_is_root(const IRef *i);
/* iref_path() is NULL for unnamed files and otherwise absolute within the root. iref_root_path() is the
 * root's resolved host path. A root iref has the path "/". Neither path is updated after an external rename
 * or a rename through another iref. */
const char* iref_path(const IRef *i);
const char* iref_root_path(const IRef *i);

/* Absolute paths start at the root of i. Nonempty relative paths require a directory and start at its
 * pinned fd. An empty path refers to the pinned inode, including a symlink itself. */

/* iref_chase() accepts lookup flags and returns chaseat()'s status. The result path is absolute within
 * the root unless filename extraction is requested. IREF_EXTRACT_FILENAME requires a valid filename;
 * IREF_EXTRACT_FILENAME_HARDER returns "." for results without a filename. A NULL ret omits the result path.
 * An empty path to an unnamed file returns -EADDRNOTAVAIL when ret is requested. */
int iref_chase(IRef *i, const char *path, IRefFlags flags, char **ret);

/* iref_open_parent(), iref_open_full(), iref_open(), and iref_fopen_unlocked() don't support
 * IREF_NONEXISTENT, IREF_STEP, IREF_PARENT, IREF_EXTRACT_FILENAME, or IREF_EXTRACT_FILENAME_HARDER. */

/* iref_open_parent() returns the resolved directory and "." when the normalized result is the root, ".",
 * or ends in "..". An empty path looks up i's tracked directory entry without following it. The parent fd
 * is O_PATH. IREF_DIRECTORY, IREF_REGULAR, and IREF_SOCKET are ignored because they describe the last component.
 * An empty path to a non-root inode accepts only IREF_NOFOLLOW and the ignored type flags. */
int iref_open_parent(IRef *i, const char *path, IRefFlags flags, IRef **ret, char **ret_filename);

/* chaseat() resolves symlinks before the final open. IREF_NOFOLLOW requires IREF_PATH to open a symlink
 * itself. IREF_DIRECTORY, IREF_REGULAR, and IREF_SOCKET apply to the opened inode. MODE_INVALID uses
 * 0644 for files and 0755 for directories, subject to the umask. IREF_TMPFILE creates an unnamed file in
 * the directory specified by path and requires IREF_WRONLY or IREF_RDWR. It doesn't support IREF_PATH,
 * IREF_CREAT, IREF_DIRECTORY, IREF_SOCKET, IREF_LABEL, IREF_SUBVOLUME, IREF_TRIGGER_AUTOFS, or IREF_AUTO_RW_RO.
 * IREF_EXCL prevents linking the unnamed file into a directory. */
int iref_open_full(IRef *i, const char *path, IRefFlags flags, mode_t mode, IRef **ret);
static inline int iref_open(IRef *i, const char *path, IRefFlags flags, IRef **ret) {
        return iref_open_full(i, path, flags, MODE_INVALID, ret);
}

/* iref_fopen_unlocked() accepts lookup flags except IREF_SOCKET. The mode specifies how to open the file. */
int iref_fopen_unlocked(IRef *i, const char *path, IRefFlags flags, const char *mode, FILE **ret);

/* Files and symlinks retain their parent iref. Directory parents are opened through ".." on demand.
 * iref_parent() and iref_parent_full() return -EINVAL when i refers to its root directory. An unnamed file
 * retains its creation directory, and iref_parent_full() returns -EADDRNOTAVAIL when ret_filename is requested. */
int iref_parent_full(IRef *i, IRef **ret, char **ret_filename);
int iref_parent(IRef *i, IRef **ret);

int iref_stat(const IRef *i, struct stat *ret);
int iref_statx(const IRef *i, int flags, unsigned mask, struct statx *ret);
int iref_statfs(const IRef *i, struct statfs *ret);
int iref_readlink(const IRef *i, char **ret);
int iref_opendir(const IRef *i, DIR **ret);
int iref_getxattr(const IRef *i, const char *name, char **ret, size_t *ret_size);
int iref_listxattr(const IRef *i, char **ret);
int iref_setxattr(const IRef *i, const char *name, const char *value, size_t size, int flags);
int iref_removexattr(const IRef *i, const char *name);
int iref_chmod_and_chown(const IRef *i, mode_t mode, uid_t uid, gid_t gid);
int iref_utimens(const IRef *i, const struct timespec times[2]);
int iref_chattr(const IRef *i, unsigned value, unsigned mask);

/* Named access, symlink, mkdir, mknod, mkfifo, unlink, and rename operations require a single filename and
 * don't follow symlinks. The filename may be "." because iref_open_parent() returns it for paths resolving
 * to the root directory. Each operation passes "." to its underlying system call and returns the result. */
/* A NULL or empty filename makes iref_access() check i itself. */
int iref_access(const IRef *i, const char *filename, int type);
int iref_symlink(const IRef *i, const char *target, const char *filename);
int iref_mkdir(const IRef *i, const char *filename, mode_t mode);
int iref_mknod(const IRef *i, const char *filename, mode_t mode, dev_t dev);
int iref_mkfifo(const IRef *i, const char *filename, mode_t mode);
/* iref_link() creates a hard link without replacing an existing entry. An unnamed iref acquires the
 * destination path, root, and parent on success. Other irefs retain their existing metadata. */
int iref_link(IRef *i, IRef *to, const char *filename);
/* A NULL or empty filename makes iref_unlink() remove i itself. iref_unlink() returns -EINVAL for the root
 * directory, -EADDRNOTAVAIL for an unnamed file, -ENOENT for a missing tracked entry, and -ESTALE for a
 * replaced inode. */
int iref_unlink(IRef *i, const char *filename, int flags);
/* A NULL or empty from_name makes iref_rename() rename from itself, with the same errors as iref_unlink().
 * Only from has its path, root, and parent updated after a self-rename. Other irefs keep their tracked paths. */
int iref_rename(IRef *from, const char *from_name, IRef *to, const char *to_name, unsigned flags);
