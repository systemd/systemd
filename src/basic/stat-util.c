/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bitfield.h"
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

        assert(fd >= 0 || IN_SET(fd, AT_FDCWD, XAT_FDROOT));
        assert(!isempty(path) || !follow);
        assert(verify_func);

        _cleanup_free_ char *p = NULL;
        r = resolve_xat_fdroot(&fd, &path, &p);
        if (r < 0)
                return r;

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
        if (IN_SET(fd, AT_FDCWD, XAT_FDROOT))
                return -EISDIR;

        return verify_regular_at(fd, /* path= */ NULL, /* follow= */ false);
}

int stat_verify_directory(const struct stat *st) {
        assert(st);

        if (S_ISLNK(st->st_mode))
                return -ELOOP;

        if (!S_ISDIR(st->st_mode))
                return -ENOTDIR;

        return 0;
}

int statx_verify_directory(const struct statx *stx) {
        assert(stx);

        if (!FLAGS_SET(stx->stx_mask, STATX_TYPE))
                return -ENODATA;

        if (S_ISLNK(stx->stx_mode))
                return -ELOOP;

        if (!S_ISDIR(stx->stx_mode))
                return -ENOTDIR;

        return 0;
}

int fd_verify_directory(int fd) {
        if (IN_SET(fd, AT_FDCWD, XAT_FDROOT))
                return 0;

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

int fd_verify_symlink(int fd) {
        return verify_stat_at(fd, /* path= */ NULL, /* follow= */ false, stat_verify_symlink, /* verify= */ true);
}

int is_symlink(const char *path) {
        assert(!isempty(path));
        return verify_stat_at(AT_FDCWD, path, false, stat_verify_symlink, false);
}

int stat_verify_socket(const struct stat *st) {
        assert(st);

        if (S_ISLNK(st->st_mode))
                return -ELOOP;

        if (S_ISDIR(st->st_mode))
                return -EISDIR;

        if (!S_ISSOCK(st->st_mode))
                return -ENOTSOCK;

        return 0;
}

int stat_verify_linked(const struct stat *st) {
        assert(st);

        if (st->st_nlink <= 0)
                return -EIDRM; /* recognizable error. */

        return 0;
}

int fd_verify_linked(int fd) {

        if (fd == XAT_FDROOT)
                return 0;

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

static const char* statx_mask_one_to_name(unsigned mask);
static const char* statx_attribute_to_name(uint64_t attr);

#include "statx-attribute-to-name.inc"
#include "statx-mask-to-name.inc"

#define DEFINE_STATX_BITS_TO_STRING(prefix, type, func, format_str)             \
        static char* prefix##_to_string(type v) {                               \
                if (v == 0)                                                     \
                        return strdup("");                                      \
                                                                                \
                _cleanup_free_ char *s = NULL;                                  \
                                                                                \
                BIT_FOREACH(i, v) {                                             \
                        type f = 1 << i;                                        \
                                                                                \
                        const char *n = func(f);                                \
                        if (!n)                                                 \
                                continue;                                       \
                                                                                \
                        if (!strextend_with_separator(&s, "|", n))              \
                                return NULL;                                    \
                        v &= ~f;                                                \
                }                                                               \
                                                                                \
                if (v != 0 && strextendf_with_separator(&s, "|", format_str, v) < 0) \
                        return NULL;                                            \
                                                                                \
                return TAKE_PTR(s);                                             \
        }

DEFINE_STATX_BITS_TO_STRING(statx_mask,       unsigned, statx_mask_one_to_name,  "0x%x");
DEFINE_STATX_BITS_TO_STRING(statx_attributes, uint64_t, statx_attribute_to_name, "0x%" PRIx64);

int xstatx_full(int fd,
                const char *path,
                int flags,
                unsigned mandatory_mask,
                unsigned optional_mask,
                uint64_t mandatory_attributes,
                struct statx *ret) {

        struct statx sx = {}; /* explicitly initialize the struct to make msan silent. */
        int r;

        /* Wrapper around statx(), with additional bells and whistles:
         *
         * 1. AT_EMPTY_PATH is implied on empty path
         * 2. Supports XAT_FDROOT
         * 3. Takes separate mandatory and optional mask params, plus mandatory attributes.
         *    Returns -EUNATCH if statx() does not return all masks specified as mandatory,
         *    > 0 if all optional masks are supported, 0 otherwise.
         */

        assert(fd >= 0 || IN_SET(fd, AT_FDCWD, XAT_FDROOT));
        assert((mandatory_mask & optional_mask) == 0);
        assert(ret);

        _cleanup_free_ char *p = NULL;
        r = resolve_xat_fdroot(&fd, &path, &p);
        if (r < 0)
                return r;

        if (statx(fd, strempty(path),
                  flags|(isempty(path) ? AT_EMPTY_PATH : 0),
                  mandatory_mask|optional_mask,
                  &sx) < 0)
                return negative_errno();

        if (!FLAGS_SET(sx.stx_mask, mandatory_mask)) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *mask_str = statx_mask_to_string(mandatory_mask & ~sx.stx_mask);
                        log_debug("statx() does not support '%s' mask (running on an old kernel?)", strnull(mask_str));
                }

                return -EUNATCH;
        }

        if (!FLAGS_SET(sx.stx_attributes_mask, mandatory_attributes)) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *attr_str = statx_attributes_to_string(mandatory_attributes & ~sx.stx_attributes_mask);
                        log_debug("statx() does not support '%s' attribute (running on an old kernel?)", strnull(attr_str));
                }

                return -EUNATCH;
        }

        *ret = sx;
        return FLAGS_SET(sx.stx_mask, optional_mask);
}

static int xfstatfs(int fd, struct statfs *ret) {
        assert(ret);

        if (fd == AT_FDCWD)
                return RET_NERRNO(statfs(".", ret));
        if (fd == XAT_FDROOT)
                return RET_NERRNO(statfs("/", ret));

        assert(fd >= 0);
        return RET_NERRNO(fstatfs(fd, ret));
}

int xstatfsat(int dir_fd, const char *path, struct statfs *ret) {
        _cleanup_close_ int fd = -EBADF;

        assert(dir_fd >= 0 || IN_SET(dir_fd, AT_FDCWD, XAT_FDROOT));
        assert(ret);

        if (!isempty(path)) {
                fd = xopenat(dir_fd, path, O_PATH|O_CLOEXEC);
                if (fd < 0)
                        return fd;
                dir_fd = fd;
        }

        return xfstatfs(dir_fd, ret);
}

int fd_is_read_only_fs(int fd) {
        int r;

        struct statfs st;
        r = xfstatfs(fd, &st);
        if (r < 0)
                return r;

        if (st.f_flags & ST_RDONLY)
                return true;

        if (is_network_fs(&st))
                /* On NFS, fstatfs() might not reflect whether we can actually write to the remote share.
                 * Let's try again with access(W_OK) which is more reliable, at least sometimes. */
                return access_fd(fd, W_OK) == -EROFS;

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
                uint64_t mntida, mntidb;
                int _mntida, _mntidb;

                r = name_to_handle_at_try_fid(
                                fda,
                                filea,
                                &ha,
                                &_mntida,
                                &mntida,
                                ntha_flags);
                if (r < 0) {
                        if (is_name_to_handle_at_fatal_error(r))
                                return r;

                        goto fallback;
                }
                if (r == 0)
                        mntida = _mntida;

                r = name_to_handle_at_try_fid(
                                fdb,
                                fileb,
                                &hb,
                                r > 0 ? NULL : &_mntidb, /* if we managed to get unique mnt id for a, insist on that for b */
                                r > 0 ? &mntidb : NULL,
                                ntha_flags);
                if (r < 0) {
                        if (is_name_to_handle_at_fatal_error(r))
                                return r;

                        goto fallback;
                }
                if (r == 0)
                        mntidb = _mntidb;

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
        int r;

        struct statfs s;
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
        int r;

        struct statfs s;
        r = xfstatfs(fd, &s);
        if (r < 0)
                return r;

        return is_temporary_fs(&s);
}

int fd_is_network_fs(int fd) {
        int r;

        struct statfs s;
        r = xfstatfs(fd, &s);
        if (r < 0)
                return r;

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

        if (!statx_is_set(a) || !statx_is_set(b))
                return false;

        assert(FLAGS_SET(a->stx_mask, STATX_TYPE|STATX_INO));
        assert(FLAGS_SET(b->stx_mask, STATX_TYPE|STATX_INO));

        return
                ((a->stx_mode ^ b->stx_mode) & S_IFMT) == 0 &&
                a->stx_dev_major == b->stx_dev_major &&
                a->stx_dev_minor == b->stx_dev_minor &&
                a->stx_ino == b->stx_ino;
}

bool statx_mount_same(const struct statx *a, const struct statx *b) {
        if (!statx_is_set(a) || !statx_is_set(b))
                return false;

        assert(FLAGS_SET(a->stx_mask, STATX_MNT_ID));
        assert(FLAGS_SET(b->stx_mask, STATX_MNT_ID));

        return a->stx_mnt_id == b->stx_mnt_id;
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
