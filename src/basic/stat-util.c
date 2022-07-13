/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "fs-util.h"
#include "macro.h"
#include "missing_fs.h"
#include "missing_magic.h"
#include "missing_syscall.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "stat-util.h"
#include "string-util.h"

int is_symlink(const char *path) {
        struct stat info;

        assert(path);

        if (lstat(path, &info) < 0)
                return -errno;

        return !!S_ISLNK(info.st_mode);
}

int is_dir_full(int atfd, const char* path, bool follow) {
        struct stat st;
        int r;

        assert(atfd >= 0 || atfd == AT_FDCWD);
        assert(atfd >= 0 || path);

        if (path)
                r = fstatat(atfd, path, &st, follow ? 0 : AT_SYMLINK_NOFOLLOW);
        else
                r = fstat(atfd, &st);
        if (r < 0)
                return -errno;

        return !!S_ISDIR(st.st_mode);
}

int is_device_node(const char *path) {
        struct stat info;

        assert(path);

        if (lstat(path, &info) < 0)
                return -errno;

        return !!(S_ISBLK(info.st_mode) || S_ISCHR(info.st_mode));
}

int dir_is_empty_at(int dir_fd, const char *path, bool ignore_hidden_or_backup) {
        _cleanup_close_ int fd = -1;
        struct dirent *buf;
        size_t m;

        if (path) {
                assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

                fd = openat(dir_fd, path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return -errno;
        } else if (dir_fd == AT_FDCWD) {
                fd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return -errno;
        } else {
                /* Note that DUPing is not enough, as the internal pointer would still be shared and moved
                 * getedents64(). */
                assert(dir_fd >= 0);

                fd = fd_reopen(dir_fd, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return fd;
        }

        /* Allocate space for at least 3 full dirents, since every dir has at least two entries ("."  +
         * ".."), and only once we have seen if there's a third we know whether the dir is empty or not. If
         * 'ignore_hidden_or_backup' is true we'll allocate a bit more, since we might skip over a bunch of
         * entries that we end up ignoring. */
        m = (ignore_hidden_or_backup ? 16 : 3) * DIRENT_SIZE_MAX;
        buf = alloca(m);

        for (;;) {
                struct dirent *de;
                ssize_t n;

                n = getdents64(fd, buf, m);
                if (n < 0)
                        return -errno;
                if (n == 0)
                        break;

                assert((size_t) n <= m);
                msan_unpoison(buf, n);

                FOREACH_DIRENT_IN_BUFFER(de, buf, n)
                        if (!(ignore_hidden_or_backup ? hidden_or_backup_file(de->d_name) : dot_or_dot_dot(de->d_name)))
                                return 0;
        }

        return 1;
}

bool null_or_empty(struct stat *st) {
        assert(st);

        if (S_ISREG(st->st_mode) && st->st_size <= 0)
                return true;

        /* We don't want to hardcode the major/minor of /dev/null, hence we do a simpler "is this a character
         * device node?" check. */

        if (S_ISCHR(st->st_mode))
                return true;

        return false;
}

int null_or_empty_path_with_root(const char *fn, const char *root) {
        struct stat st;
        int r;

        assert(fn);

        /* A symlink to /dev/null or an empty file?
         * When looking under root_dir, we can't expect /dev/ to be mounted,
         * so let's see if the path is a (possibly dangling) symlink to /dev/null. */

        if (path_equal_ptr(path_startswith(fn, root ?: "/"), "dev/null"))
                return true;

        r = chase_symlinks_and_stat(fn, root, CHASE_PREFIX_ROOT, NULL, &st, NULL);
        if (r < 0)
                return r;

        return null_or_empty(&st);
}

int null_or_empty_fd(int fd) {
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        return null_or_empty(&st);
}

int path_is_read_only_fs(const char *path) {
        struct statvfs st;

        assert(path);

        if (statvfs(path, &st) < 0)
                return -errno;

        if (st.f_flag & ST_RDONLY)
                return true;

        /* On NFS, statvfs() might not reflect whether we can actually
         * write to the remote share. Let's try again with
         * access(W_OK) which is more reliable, at least sometimes. */
        if (access(path, W_OK) < 0 && errno == EROFS)
                return true;

        return false;
}

int files_same(const char *filea, const char *fileb, int flags) {
        struct stat a, b;

        assert(filea);
        assert(fileb);

        if (fstatat(AT_FDCWD, filea, &a, flags) < 0)
                return -errno;

        if (fstatat(AT_FDCWD, fileb, &b, flags) < 0)
                return -errno;

        return stat_inode_same(&a, &b);
}

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) {
        assert(s);
        assert_cc(sizeof(statfs_f_type_t) >= sizeof(s->f_type));

        return F_TYPE_EQUAL(s->f_type, magic_value);
}

int fd_is_fs_type(int fd, statfs_f_type_t magic_value) {
        struct statfs s;

        if (fstatfs(fd, &s) < 0)
                return -errno;

        return is_fs_type(&s, magic_value);
}

int path_is_fs_type(const char *path, statfs_f_type_t magic_value) {
        struct statfs s;

        if (statfs(path, &s) < 0)
                return -errno;

        return is_fs_type(&s, magic_value);
}

bool is_temporary_fs(const struct statfs *s) {
        return fs_in_group(s, FILESYSTEM_SET_TEMPORARY);
}

bool is_network_fs(const struct statfs *s) {
        return fs_in_group(s, FILESYSTEM_SET_NETWORK);
}

int fd_is_temporary_fs(int fd) {
        struct statfs s;

        if (fstatfs(fd, &s) < 0)
                return -errno;

        return is_temporary_fs(&s);
}

int fd_is_network_fs(int fd) {
        struct statfs s;

        if (fstatfs(fd, &s) < 0)
                return -errno;

        return is_network_fs(&s);
}

int path_is_temporary_fs(const char *path) {
        struct statfs s;

        if (statfs(path, &s) < 0)
                return -errno;

        return is_temporary_fs(&s);
}

int path_is_network_fs(const char *path) {
        struct statfs s;

        if (statfs(path, &s) < 0)
                return -errno;

        return is_network_fs(&s);
}

int stat_verify_regular(const struct stat *st) {
        assert(st);

        /* Checks whether the specified stat() structure refers to a regular file. If not returns an appropriate error
         * code. */

        if (S_ISDIR(st->st_mode))
                return -EISDIR;

        if (S_ISLNK(st->st_mode))
                return -ELOOP;

        if (!S_ISREG(st->st_mode))
                return -EBADFD;

        return 0;
}

int fd_verify_regular(int fd) {
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        return stat_verify_regular(&st);
}

int stat_verify_directory(const struct stat *st) {
        assert(st);

        if (S_ISLNK(st->st_mode))
                return -ELOOP;

        if (!S_ISDIR(st->st_mode))
                return -ENOTDIR;

        return 0;
}

int fd_verify_directory(int fd) {
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        return stat_verify_directory(&st);
}

int proc_mounted(void) {
        int r;

        /* A quick check of procfs is properly mounted */

        r = path_is_fs_type("/proc/", PROC_SUPER_MAGIC);
        if (r == -ENOENT) /* not mounted at all */
                return false;

        return r;
}

bool stat_inode_same(const struct stat *a, const struct stat *b) {

        /* Returns if the specified stat structure references the same (though possibly modified) inode. Does
         * a thorough check, comparing inode nr, backing device and if the inode is still of the same type. */

        return a && b &&
                (a->st_mode & S_IFMT) != 0 && /* We use the check for .st_mode if the structure was ever initialized */
                ((a->st_mode ^ b->st_mode) & S_IFMT) == 0 &&  /* same inode type */
                a->st_dev == b->st_dev &&
                a->st_ino == b->st_ino;
}

bool stat_inode_unmodified(const struct stat *a, const struct stat *b) {

        /* Returns if the specified stat structures reference the same, unmodified inode. This check tries to
         * be reasonably careful when detecting changes: we check both inode and mtime, to cater for file
         * systems where mtimes are fixed to 0 (think: ostree/nixos type installations). We also check file
         * size, backing device, inode type and if this refers to a device not the major/minor.
         *
         * Note that we don't care if file attributes such as ownership or access mode change, this here is
         * about contents of the file. The purpose here is to detect file contents changes, and nothing
         * else. */

        return stat_inode_same(a, b) &&
                a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
                a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
                (!S_ISREG(a->st_mode) || a->st_size == b->st_size) && /* if regular file, compare file size */
                (!(S_ISCHR(a->st_mode) || S_ISBLK(a->st_mode)) || a->st_rdev == b->st_rdev); /* if device node, also compare major/minor, because we can */
}

int statx_fallback(int dfd, const char *path, int flags, unsigned mask, struct statx *sx) {
        static bool avoid_statx = false;
        struct stat st;

        if (!avoid_statx) {
                if (statx(dfd, path, flags, mask, sx) < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EPERM)
                                return -errno;

                        /* If statx() is not supported or if we see EPERM (which might indicate seccomp
                         * filtering or so), let's do a fallback. Not that on EACCES we'll not fall back,
                         * since that is likely an indication of fs access issues, which we should
                         * propagate */
                } else
                        return 0;

                avoid_statx = true;
        }

        /* Only do fallback if fstatat() supports the flag too, or if it's one of the sync flags, which are
         * OK to ignore */
        if ((flags & ~(AT_EMPTY_PATH|AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW|
                      AT_STATX_SYNC_AS_STAT|AT_STATX_FORCE_SYNC|AT_STATX_DONT_SYNC)) != 0)
                return -EOPNOTSUPP;

        if (fstatat(dfd, path, &st, flags & (AT_EMPTY_PATH|AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW)) < 0)
                return -errno;

        *sx = (struct statx) {
                .stx_mask = STATX_TYPE|STATX_MODE|
                STATX_NLINK|STATX_UID|STATX_GID|
                STATX_ATIME|STATX_MTIME|STATX_CTIME|
                STATX_INO|STATX_SIZE|STATX_BLOCKS,
                .stx_blksize = st.st_blksize,
                .stx_nlink = st.st_nlink,
                .stx_uid = st.st_uid,
                .stx_gid = st.st_gid,
                .stx_mode = st.st_mode,
                .stx_ino = st.st_ino,
                .stx_size = st.st_size,
                .stx_blocks = st.st_blocks,
                .stx_rdev_major = major(st.st_rdev),
                .stx_rdev_minor = minor(st.st_rdev),
                .stx_dev_major = major(st.st_dev),
                .stx_dev_minor = minor(st.st_dev),
                .stx_atime.tv_sec = st.st_atim.tv_sec,
                .stx_atime.tv_nsec = st.st_atim.tv_nsec,
                .stx_mtime.tv_sec = st.st_mtim.tv_sec,
                .stx_mtime.tv_nsec = st.st_mtim.tv_nsec,
                .stx_ctime.tv_sec = st.st_ctim.tv_sec,
                .stx_ctime.tv_nsec = st.st_ctim.tv_nsec,
        };

        return 0;
}
