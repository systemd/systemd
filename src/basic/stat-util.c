/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "missing_fs.h"
#include "missing_magic.h"
#include "missing_syscall.h"
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

int is_dir(const char* path, bool follow) {
        struct stat st;
        int r;

        assert(path);

        if (follow)
                r = stat(path, &st);
        else
                r = lstat(path, &st);
        if (r < 0)
                return -errno;

        return !!S_ISDIR(st.st_mode);
}

int is_dir_fd(int fd) {
        struct stat st;

        if (fstat(fd, &st) < 0)
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

int dir_is_empty_at(int dir_fd, const char *path) {
        _cleanup_close_ int fd = -1;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;

        if (path) {
                fd = openat(dir_fd, path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return -errno;
        } else {
                /* Note that DUPing is not enough, as the internal pointer
                 * would still be shared and moved by FOREACH_DIRENT. */
                fd = fd_reopen(dir_fd, O_CLOEXEC);
                if (fd < 0)
                        return fd;
        }

        d = take_fdopendir(&fd);
        if (!d)
                return -errno;

        FOREACH_DIRENT(de, d, return -errno)
                return 0;

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

int null_or_empty_path(const char *fn) {
        struct stat st;

        assert(fn);

        /* If we have the path, let's do an easy text comparison first. */
        if (path_equal(fn, "/dev/null"))
                return true;

        if (stat(fn, &st) < 0)
                return -errno;

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

        return a.st_dev == b.st_dev &&
               a.st_ino == b.st_ino;
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
        return is_fs_type(s, TMPFS_MAGIC) ||
                is_fs_type(s, RAMFS_MAGIC);
}

bool is_network_fs(const struct statfs *s) {
        return is_fs_type(s, CIFS_MAGIC_NUMBER) ||
                is_fs_type(s, CODA_SUPER_MAGIC) ||
                is_fs_type(s, NCP_SUPER_MAGIC) ||
                is_fs_type(s, NFS_SUPER_MAGIC) ||
                is_fs_type(s, SMB_SUPER_MAGIC) ||
                is_fs_type(s, V9FS_MAGIC) ||
                is_fs_type(s, AFS_SUPER_MAGIC) ||
                is_fs_type(s, OCFS2_SUPER_MAGIC);
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

int device_path_make_major_minor(mode_t mode, dev_t devno, char **ret) {
        const char *t;

        /* Generates the /dev/{char|block}/MAJOR:MINOR path for a dev_t */

        if (S_ISCHR(mode))
                t = "char";
        else if (S_ISBLK(mode))
                t = "block";
        else
                return -ENODEV;

        if (asprintf(ret, "/dev/%s/%u:%u", t, major(devno), minor(devno)) < 0)
                return -ENOMEM;

        return 0;
}

int device_path_make_canonical(mode_t mode, dev_t devno, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        /* Finds the canonical path for a device, i.e. resolves the /dev/{char|block}/MAJOR:MINOR path to the end. */

        assert(ret);

        if (major(devno) == 0 && minor(devno) == 0) {
                char *s;

                /* A special hack to make sure our 'inaccessible' device nodes work. They won't have symlinks in
                 * /dev/block/ and /dev/char/, hence we handle them specially here. */

                if (S_ISCHR(mode))
                        s = strdup("/run/systemd/inaccessible/chr");
                else if (S_ISBLK(mode))
                        s = strdup("/run/systemd/inaccessible/blk");
                else
                        return -ENODEV;

                if (!s)
                        return -ENOMEM;

                *ret = s;
                return 0;
        }

        r = device_path_make_major_minor(mode, devno, &p);
        if (r < 0)
                return r;

        return chase_symlinks(p, NULL, 0, ret, NULL);
}

int device_path_parse_major_minor(const char *path, mode_t *ret_mode, dev_t *ret_devno) {
        mode_t mode;
        dev_t devno;
        int r;

        /* Tries to extract the major/minor directly from the device path if we can. Handles /dev/block/ and /dev/char/
         * paths, as well out synthetic inaccessible device nodes. Never goes to disk. Returns -ENODEV if the device
         * path cannot be parsed like this.  */

        if (path_equal(path, "/run/systemd/inaccessible/chr")) {
                mode = S_IFCHR;
                devno = makedev(0, 0);
        } else if (path_equal(path, "/run/systemd/inaccessible/blk")) {
                mode = S_IFBLK;
                devno = makedev(0, 0);
        } else {
                const char *w;

                w = path_startswith(path, "/dev/block/");
                if (w)
                        mode = S_IFBLK;
                else {
                        w = path_startswith(path, "/dev/char/");
                        if (!w)
                                return -ENODEV;

                        mode = S_IFCHR;
                }

                r = parse_dev(w, &devno);
                if (r < 0)
                        return r;
        }

        if (ret_mode)
                *ret_mode = mode;
        if (ret_devno)
                *ret_devno = devno;

        return 0;
}

int proc_mounted(void) {
        int r;

        /* A quick check of procfs is properly mounted */

        r = path_is_fs_type("/proc/", PROC_SUPER_MAGIC);
        if (r == -ENOENT) /* not mounted at all */
                return false;

        return r;
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

        return a && b &&
                (a->st_mode & S_IFMT) != 0 && /* We use the check for .st_mode if the structure was ever initialized */
                ((a->st_mode ^ b->st_mode) & S_IFMT) == 0 &&  /* same inode type */
                a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
                a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
                (!S_ISREG(a->st_mode) || a->st_size == b->st_size) && /* if regular file, compare file size */
                a->st_dev == b->st_dev &&
                a->st_ino == b->st_ino &&
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
