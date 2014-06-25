/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"
#include "copy.h"

int copy_bytes(int fdf, int fdt, off_t max_bytes) {
        assert(fdf >= 0);
        assert(fdt >= 0);

        for (;;) {
                char buf[PIPE_BUF];
                ssize_t n, k;
                size_t m = sizeof(buf);

                if (max_bytes != (off_t) -1) {

                        if (max_bytes <= 0)
                                return -E2BIG;

                        if ((off_t) m > max_bytes)
                                m = (size_t) max_bytes;
                }

                n = read(fdf, buf, m);
                if (n < 0)
                        return -errno;
                if (n == 0)
                        break;

                errno = 0;
                k = loop_write(fdt, buf, n, false);
                if (k < 0)
                        return k;
                if (k != n)
                        return errno ? -errno : -EIO;

                if (max_bytes != (off_t) -1) {
                        assert(max_bytes >= n);
                        max_bytes -= n;
                }
        }

        return 0;
}

static int fd_copy_symlink(int df, const char *from, const struct stat *st, int dt, const char *to) {
        _cleanup_free_ char *target = NULL;
        int r;

        assert(from);
        assert(st);
        assert(to);

        r = readlinkat_malloc(df, from, &target);
        if (r < 0)
                return r;

        if (symlinkat(target, dt, to) < 0)
                return -errno;

        if (fchownat(dt, to, st->st_uid, st->st_gid, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        return 0;
}

static int fd_copy_regular(int df, const char *from, const struct stat *st, int dt, const char *to) {
        _cleanup_close_ int fdf = -1, fdt = -1;
        int r, q;

        assert(from);
        assert(st);
        assert(to);

        fdf = openat(df, from, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fdf < 0)
                return -errno;

        fdt = openat(dt, to, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, st->st_mode & 07777);
        if (fdt < 0)
                return -errno;

        r = copy_bytes(fdf, fdt, (off_t) -1);
        if (r < 0) {
                unlinkat(dt, to, 0);
                return r;
        }

        if (fchown(fdt, st->st_uid, st->st_gid) < 0)
                r = -errno;

        if (fchmod(fdt, st->st_mode & 07777) < 0)
                r = -errno;

        q = close(fdt);
        fdt = -1;

        if (q < 0) {
                r = -errno;
                unlinkat(dt, to, 0);
        }

        return r;
}

static int fd_copy_fifo(int df, const char *from, const struct stat *st, int dt, const char *to) {
        int r;

        assert(from);
        assert(st);
        assert(to);

        r = mkfifoat(dt, to, st->st_mode & 07777);
        if (r < 0)
                return -errno;

        if (fchownat(dt, to, st->st_uid, st->st_gid, AT_SYMLINK_NOFOLLOW) < 0)
                r = -errno;

        if (fchmodat(dt, to, st->st_mode & 07777, 0) < 0)
                r = -errno;

        return r;
}

static int fd_copy_node(int df, const char *from, const struct stat *st, int dt, const char *to) {
        int r;

        assert(from);
        assert(st);
        assert(to);

        r = mknodat(dt, to, st->st_mode, st->st_rdev);
        if (r < 0)
                return -errno;

        if (fchownat(dt, to, st->st_uid, st->st_gid, AT_SYMLINK_NOFOLLOW) < 0)
                r = -errno;

        if (fchmodat(dt, to, st->st_mode & 07777, 0) < 0)
                r = -errno;

        return r;
}

static int fd_copy_directory(int df, const char *from, const struct stat *st, int dt, const char *to, dev_t original_device, bool merge) {
        _cleanup_close_ int fdf = -1, fdt = -1;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        bool created;
        int r;

        assert(from);
        assert(st);
        assert(to);

        fdf = openat(df, from, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fdf < 0)
                return -errno;

        d = fdopendir(fdf);
        if (!d)
                return -errno;
        fdf = -1;

        r = mkdirat(dt, to, st->st_mode & 07777);
        if (r >= 0)
                created = true;
        else if (errno == EEXIST && merge)
                created = false;
        else
                return -errno;

        fdt = openat(dt, to, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fdt < 0)
                return -errno;

        r = 0;

        if (created) {
                if (fchown(fdt, st->st_uid, st->st_gid) < 0)
                        r = -errno;

                if (fchmod(fdt, st->st_mode & 07777) < 0)
                        r = -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                struct stat buf;
                int q;

                if (fstatat(dirfd(d), de->d_name, &buf, AT_SYMLINK_NOFOLLOW) < 0) {
                        r = -errno;
                        continue;
                }

                if (buf.st_dev != original_device)
                        continue;

                if (S_ISREG(buf.st_mode))
                        q = fd_copy_regular(dirfd(d), de->d_name, &buf, fdt, de->d_name);
                else if (S_ISDIR(buf.st_mode))
                        q = fd_copy_directory(dirfd(d), de->d_name, &buf, fdt, de->d_name, original_device, merge);
                else if (S_ISLNK(buf.st_mode))
                        q = fd_copy_symlink(dirfd(d), de->d_name, &buf, fdt, de->d_name);
                else if (S_ISFIFO(buf.st_mode))
                        q = fd_copy_fifo(dirfd(d), de->d_name, &buf, fdt, de->d_name);
                else if (S_ISBLK(buf.st_mode) || S_ISCHR(buf.st_mode))
                        q = fd_copy_node(dirfd(d), de->d_name, &buf, fdt, de->d_name);
                else
                        q = -ENOTSUP;

                if (q == -EEXIST && merge)
                        q = 0;

                if (q < 0)
                        r = q;
        }

        return r;
}

int copy_tree(const char *from, const char *to, bool merge) {
        struct stat st;

        assert(from);
        assert(to);

        if (lstat(from, &st) < 0)
                return -errno;

        if (S_ISREG(st.st_mode))
                return fd_copy_regular(AT_FDCWD, from, &st, AT_FDCWD, to);
        else if (S_ISDIR(st.st_mode))
                return fd_copy_directory(AT_FDCWD, from, &st, AT_FDCWD, to, st.st_dev, merge);
        else if (S_ISLNK(st.st_mode))
                return fd_copy_symlink(AT_FDCWD, from, &st, AT_FDCWD, to);
        else if (S_ISFIFO(st.st_mode))
                return fd_copy_fifo(AT_FDCWD, from, &st, AT_FDCWD, to);
        else if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))
                return fd_copy_node(AT_FDCWD, from, &st, AT_FDCWD, to);
        else
                return -ENOTSUP;
}

int copy_file(const char *from, const char *to, int flags, mode_t mode) {
        _cleanup_close_ int fdf = -1, fdt = -1;
        int r;

        assert(from);
        assert(to);

        fdf = open(from, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fdf < 0)
                return -errno;

        fdt = open(to, flags|O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, mode);
        if (fdt < 0)
                return -errno;

        r = copy_bytes(fdf, fdt, (off_t) -1);
        if (r < 0) {
                unlink(to);
                return r;
        }

        r = close(fdt);
        fdt = -1;

        if (r < 0) {
                r = -errno;
                unlink(to);
                return r;
        }

        return 0;
}
