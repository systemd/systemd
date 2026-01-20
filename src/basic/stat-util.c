/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "filesystems.h"
#include "fs-util.h"
#include "hash-funcs.h"
#include "log.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "siphash24.h"
#include "stat-util.h"
#include "string-util.h"
#include "time-util.h"

static int verify_stat_at(
                int fd,
                const char *path,
                bool follow,
                int (*verify_func)(const struct stat *st),
                bool verify) {

        struct stat st;
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert(!isempty(path) || !follow);
        assert(verify_func);

        if (fstatat(fd, strempty(path), &st,
                    (isempty(path) ? AT_EMPTY_PATH : 0) | (follow ? 0 : AT_SYMLINK_NOFOLLOW)) < 0)
                return -errno;

        r = verify_func(&st);
        return verify ? r : r >= 0;
}

int stat_verify_regular(const struct stat *st) {
        assert(st);

        /* Checks whether the specified stat() structure refers to a regular file. If not returns an
         * appropriate error code. */

        if (S_ISDIR(st->st_mode))
                return -EISDIR;

        if (S_ISLNK(st->st_mode))
                return -ELOOP;

        if (!S_ISREG(st->st_mode))
                return -EBADFD;

        return 0;
}

int verify_regular_at(int fd, const char *path, bool follow) {
        return verify_stat_at(fd, path, follow, stat_verify_regular, true);
}

int fd_verify_regular(int fd) {
        assert(fd >= 0);
        return verify_regular_at(fd, NULL, false);
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
        assert(fd >= 0);
        return verify_stat_at(fd, NULL, false, stat_verify_directory, true);
}

int is_dir_at(int fd, const char *path, bool follow) {
        return verify_stat_at(fd, path, follow, stat_verify_directory, false);
}

int is_dir(const char *path, bool follow) {
        assert(!isempty(path));
        return is_dir_at(AT_FDCWD, path, follow);
}

int stat_verify_symlink(const struct stat *st) {
        assert(st);

        if (S_ISDIR(st->st_mode))
                return -EISDIR;

        if (!S_ISLNK(st->st_mode))
                return -ENOLINK;

        return 0;
}

int is_symlink(const char *path) {
        assert(!isempty(path));
        return verify_stat_at(AT_FDCWD, path, false, stat_verify_symlink, false);
}

int stat_verify_linked(const struct stat *st) {
        assert(st);

        if (st->st_nlink <= 0)
                return -EIDRM; /* recognizable error. */

        return 0;
}

int fd_verify_linked(int fd) {
        assert(fd >= 0);
        return verify_stat_at(fd, NULL, false, stat_verify_linked, true);
}

int stat_verify_device_node(const struct stat *st) {
        assert(st);

        if (S_ISLNK(st->st_mode))
                return -ELOOP;

        if (S_ISDIR(st->st_mode))
                return -EISDIR;

        if (!S_ISBLK(st->st_mode) && !S_ISCHR(st->st_mode))
                return -ENOTTY;

        return 0;
}

int is_device_node(const char *path) {
        assert(!isempty(path));
        return verify_stat_at(AT_FDCWD, path, false, stat_verify_device_node, false);
}

int dir_is_empty_at(int dir_fd, const char *path, bool ignore_hidden_or_backup) {
        _cleanup_close_ int fd = -EBADF;
        struct dirent *buf;
        size_t m;

        fd = xopenat(dir_fd, path, O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return fd;

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

bool stat_may_be_dev_null(struct stat *st) {
        assert(st);

        /* We don't want to hardcode the major/minor of /dev/null, hence we do a simpler "is this a character
         * device node?" check. */

        return S_ISCHR(st->st_mode);
}

bool stat_is_empty(struct stat *st) {
        assert(st);

        return S_ISREG(st->st_mode) && st->st_size <= 0;
}

int null_or_empty_path_with_root(const char *fn, const char *root) {
        struct stat st;
        int r;

        assert(fn);

        /* A symlink to /dev/null or an empty file?
         * When looking under root_dir, we can't expect /dev/ to be mounted,
         * so let's see if the path is a (possibly dangling) symlink to /dev/null. */

        if (path_equal(path_startswith(fn, root ?: "/"), "dev/null"))
                return true;

        r = chase_and_stat(fn, root, CHASE_PREFIX_ROOT, NULL, &st);
        if (r < 0)
                return r;

        return null_or_empty(&st);
}

int fd_is_read_only_fs(int fd) {
        struct statfs st;

        assert(fd >= 0);

        if (fstatfs(fd, &st) < 0)
                return -errno;

        if (st.f_flags & ST_RDONLY)
                return true;

        if (is_network_fs(&st)) {
                /* On NFS, fstatfs() might not reflect whether we can actually write to the remote share.
                 * Let's try again with access(W_OK) which is more reliable, at least sometimes. */
                if (access_fd(fd, W_OK) == -EROFS)
                        return true;
        }

        return false;
}

int path_is_read_only_fs(const char *path) {
        _cleanup_close_ int fd = -EBADF;

        assert(path);

        fd = open(path, O_CLOEXEC | O_PATH);
        if (fd < 0)
                return -errno;

        return fd_is_read_only_fs(fd);
}

int inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags) {
        struct stat sta, stb;
        int r;

        assert(fda >= 0 || fda == AT_FDCWD);
        assert(fdb >= 0 || fdb == AT_FDCWD);
        assert((flags & ~(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT)) == 0);

        /* Refuse an unset filea or fileb early unless AT_EMPTY_PATH is set */
        if ((isempty(filea) || isempty(fileb)) && !FLAGS_SET(flags, AT_EMPTY_PATH))
                return -EINVAL;

        /* Shortcut: comparing the same fd with itself means we can return true */
        if (fda >= 0 && fda == fdb && isempty(filea) && isempty(fileb) && FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW))
                return true;

        _cleanup_close_ int pin_a = -EBADF, pin_b = -EBADF;
        if (!FLAGS_SET(flags, AT_NO_AUTOMOUNT)) {
                /* Let's try to use the name_to_handle_at() AT_HANDLE_FID API to identify identical
                 * inodes. We have to issue multiple calls on the same file for that (first, to acquire the
                 * FID, and then to check if .st_dev is actually the same). Hence let's pin the inode in
                 * between via O_PATH, unless we already have an fd for it. */

                if (!isempty(filea)) {
                        pin_a = openat(fda, filea, O_PATH|O_CLOEXEC|(FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0));
                        if (pin_a < 0)
                                return -errno;

                        fda = pin_a;
                        filea = NULL;
                        flags |= AT_EMPTY_PATH;
                }

                if (!isempty(fileb)) {
                        pin_b = openat(fdb, fileb, O_PATH|O_CLOEXEC|(FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0));
                        if (pin_b < 0)
                                return -errno;

                        fdb = pin_b;
                        fileb = NULL;
                        flags |= AT_EMPTY_PATH;
                }

                int ntha_flags = at_flags_normalize_follow(flags) & (AT_EMPTY_PATH|AT_SYMLINK_FOLLOW);
                _cleanup_free_ struct file_handle *ha = NULL, *hb = NULL;
                int mntida = -1, mntidb = -1;

                r = name_to_handle_at_try_fid(
                                fda,
                                filea,
                                &ha,
                                &mntida,
                                ntha_flags);
                if (r < 0) {
                        if (is_name_to_handle_at_fatal_error(r))
                                return r;

                        goto fallback;
                }

                r = name_to_handle_at_try_fid(
                                fdb,
                                fileb,
                                &hb,
                                &mntidb,
                                ntha_flags);
                if (r < 0) {
                        if (is_name_to_handle_at_fatal_error(r))
                                return r;

                        goto fallback;
                }

                /* Now compare the two file handles */
                if (!file_handle_equal(ha, hb))
                        return false;

                /* If the file handles are the same and they come from the same mount ID? Great, then we are
                 * good, they are definitely the same */
                if (mntida == mntidb)
                        return true;

                /* File handles are the same, they are not on the same mount id. This might either be because
                 * they are on two entirely different file systems, that just happen to have the same FIDs
                 * (because they originally where created off the same disk images), or it could be because
                 * they are located on two distinct bind mounts of the same fs. To check that, let's look at
                 * .st_rdev of the inode. We simply reuse the fallback codepath for that, since it checks
                 * exactly that (it checks slightly more, but we don't care.) */
        }

fallback:
        if (fstatat(fda, strempty(filea), &sta, flags) < 0)
                return log_debug_errno(errno, "Cannot stat %s: %m", strna(filea));

        if (fstatat(fdb, strempty(fileb), &stb, flags) < 0)
                return log_debug_errno(errno, "Cannot stat %s: %m", strna(fileb));

        return stat_inode_same(&sta, &stb);
}

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) {
        assert(s);
        assert_cc(sizeof(statfs_f_type_t) >= sizeof(s->f_type));

        return F_TYPE_EQUAL(s->f_type, magic_value);
}

int is_fs_type_at(int dir_fd, const char *path, statfs_f_type_t magic_value) {
        struct statfs s;
        int r;

        r = xstatfsat(dir_fd, path, &s);
        if (r < 0)
                return r;

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

int proc_mounted(void) {
        /* This is typically used in error path. So, it is better to not overwrite the original errno. */
        PROTECT_ERRNO;
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

        return stat_is_set(a) && stat_is_set(b) &&
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

bool statx_inode_same(const struct statx *a, const struct statx *b) {

        /* Same as stat_inode_same() but for struct statx */

        return statx_is_set(a) && statx_is_set(b) &&
                FLAGS_SET(a->stx_mask, STATX_TYPE|STATX_INO) && FLAGS_SET(b->stx_mask, STATX_TYPE|STATX_INO) &&
                ((a->stx_mode ^ b->stx_mode) & S_IFMT) == 0 &&
                a->stx_dev_major == b->stx_dev_major &&
                a->stx_dev_minor == b->stx_dev_minor &&
                a->stx_ino == b->stx_ino;
}

bool statx_mount_same(const struct statx *a, const struct statx *b) {
        if (!statx_is_set(a) || !statx_is_set(b))
                return false;

        /* if we have the mount ID, that's all we need */
        if (FLAGS_SET(a->stx_mask, STATX_MNT_ID) && FLAGS_SET(b->stx_mask, STATX_MNT_ID))
                return a->stx_mnt_id == b->stx_mnt_id;

        /* Otherwise, major/minor of backing device must match */
        return a->stx_dev_major == b->stx_dev_major &&
                a->stx_dev_minor == b->stx_dev_minor;
}

int xstatfsat(int dir_fd, const char *path, struct statfs *ret) {
        _cleanup_close_ int fd = -EBADF;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        if (!isempty(path)) {
                fd = xopenat(dir_fd, path, O_PATH|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return fd;
                dir_fd = fd;
        }

        return RET_NERRNO(fstatfs(dir_fd, ret));
}

usec_t statx_timestamp_load(const struct statx_timestamp *ts) {
        return timespec_load(&(const struct timespec) { .tv_sec = ts->tv_sec, .tv_nsec = ts->tv_nsec });
}
nsec_t statx_timestamp_load_nsec(const struct statx_timestamp *ts) {
        return timespec_load_nsec(&(const struct timespec) { .tv_sec = ts->tv_sec, .tv_nsec = ts->tv_nsec });
}

void inode_hash_func(const struct stat *q, struct siphash *state) {
        siphash24_compress_typesafe(q->st_dev, state);
        siphash24_compress_typesafe(q->st_ino, state);
}

int inode_compare_func(const struct stat *a, const struct stat *b) {
        int r;

        r = CMP(a->st_dev, b->st_dev);
        if (r != 0)
                return r;

        return CMP(a->st_ino, b->st_ino);
}

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(inode_hash_ops, struct stat, inode_hash_func, inode_compare_func, free);

const char* inode_type_to_string(mode_t m) {

        /* Returns a short string for the inode type. We use the same name as the underlying macros for each
         * inode type. */

        switch (m & S_IFMT) {
        case S_IFREG:
                return "reg";
        case S_IFDIR:
                return "dir";
        case S_IFLNK:
                return "lnk";
        case S_IFCHR:
                return "chr";
        case S_IFBLK:
                return "blk";
        case S_IFIFO:
                return "fifo";
        case S_IFSOCK:
                return "sock";
        }

        /* Note anonymous inodes in the kernel will have a zero type. Hence fstat() of an eventfd() will
         * return an .st_mode where we'll return NULL here! */
        return NULL;
}

mode_t inode_type_from_string(const char *s) {
        if (!s)
                return MODE_INVALID;

        if (streq(s, "reg"))
                return S_IFREG;
        if (streq(s, "dir"))
                return S_IFDIR;
        if (streq(s, "lnk"))
                return S_IFLNK;
        if (streq(s, "chr"))
                return S_IFCHR;
        if (streq(s, "blk"))
                return S_IFBLK;
        if (streq(s, "fifo"))
                return S_IFIFO;
        if (streq(s, "sock"))
                return S_IFSOCK;

        return MODE_INVALID;
}
