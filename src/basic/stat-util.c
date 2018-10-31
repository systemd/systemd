/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "missing.h"
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

int dir_is_empty(const char *path) {
        _cleanup_closedir_ DIR *d;
        struct dirent *de;

        d = opendir(path);
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

        /* We don't want to hardcode the major/minor of /dev/null,
         * hence we do a simpler "is this a device node?" check. */

        if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode))
                return true;

        return false;
}

int null_or_empty_path(const char *fn) {
        struct stat st;

        assert(fn);

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
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_PATH);
        if (fd < 0)
                return -errno;

        return fd_is_fs_type(fd, magic_value);
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

int fd_is_network_ns(int fd) {
        struct statfs s;
        int r;

        /* Checks whether the specified file descriptor refers to a network namespace. On old kernels there's no nice
         * way to detect that, hence on those we'll return a recognizable error (EUCLEAN), so that callers can handle
         * this somewhat nicely.
         *
         * This function returns > 0 if the fd definitely refers to a network namespace, 0 if it definitely does not
         * refer to a network namespace, -EUCLEAN if we can't determine, and other negative error codes on error. */

        if (fstatfs(fd, &s) < 0)
                return -errno;

        if (!is_fs_type(&s, NSFS_MAGIC)) {
                /* On really old kernels, there was no "nsfs", and network namespace sockets belonged to procfs
                 * instead. Handle that in a somewhat smart way. */

                if (is_fs_type(&s, PROC_SUPER_MAGIC)) {
                        struct statfs t;

                        /* OK, so it is procfs. Let's see if our own network namespace is procfs, too. If so, then the
                         * passed fd might refer to a network namespace, but we can't know for sure. In that case,
                         * return a recognizable error. */

                        if (statfs("/proc/self/ns/net", &t) < 0)
                                return -errno;

                        if (s.f_type == t.f_type)
                                return -EUCLEAN; /* It's possible, we simply don't know */
                }

                return 0; /* No! */
        }

        r = ioctl(fd, NS_GET_NSTYPE);
        if (r < 0) {
                if (errno == ENOTTY) /* Old kernels didn't know this ioctl, let's also return a recognizable error in that case */
                        return -EUCLEAN;

                return -errno;
        }

        return r == CLONE_NEWNET;
}

int path_is_temporary_fs(const char *path) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_PATH);
        if (fd < 0)
                return -errno;

        return fd_is_temporary_fs(fd);
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
