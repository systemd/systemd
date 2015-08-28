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

#include <sys/sendfile.h>
#include <sys/xattr.h>

#include "util.h"
#include "btrfs-util.h"
#include "strv.h"
#include "copy.h"

#define COPY_BUFFER_SIZE (16*1024)

int copy_bytes(int fdf, int fdt, off_t max_bytes, bool try_reflink) {
        bool try_sendfile = true, try_splice = true;
        int r;

        assert(fdf >= 0);
        assert(fdt >= 0);

        /* Try btrfs reflinks first. */
        if (try_reflink && max_bytes == (off_t) -1) {
                r = btrfs_reflink(fdf, fdt);
                if (r >= 0)
                        return r;
        }

        for (;;) {
                size_t m = COPY_BUFFER_SIZE;
                ssize_t n;

                if (max_bytes != (off_t) -1) {

                        if (max_bytes <= 0)
                                return -EFBIG;

                        if ((off_t) m > max_bytes)
                                m = (size_t) max_bytes;
                }

                /* First try sendfile(), unless we already tried */
                if (try_sendfile) {

                        n = sendfile(fdt, fdf, NULL, m);
                        if (n < 0) {
                                if (errno != EINVAL && errno != ENOSYS)
                                        return -errno;

                                try_sendfile = false;
                                /* use fallback below */
                        } else if (n == 0) /* EOF */
                                break;
                        else if (n > 0)
                                /* Success! */
                                goto next;
                }

                /* The try splice, unless we already tried */
                if (try_splice) {
                        n  = splice(fdf, NULL, fdt, NULL, m, 0);
                        if (n < 0) {
                                if (errno != EINVAL && errno != ENOSYS)
                                        return -errno;

                                try_splice = false;
                                /* use fallback below */
                        } else if (n == 0) /* EOF */
                                break;
                        else if (n > 0)
                                /* Success! */
                                goto next;
                }

                /* As a fallback just copy bits by hand */
                {
                        char buf[m];

                        n = read(fdf, buf, m);
                        if (n < 0)
                                return -errno;
                        if (n == 0) /* EOF */
                                break;

                        r = loop_write(fdt, buf, (size_t) n, false);
                        if (r < 0)
                                return r;
                }

        next:
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
        struct timespec ts[2];
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

        r = copy_bytes(fdf, fdt, (off_t) -1, true);
        if (r < 0) {
                unlinkat(dt, to, 0);
                return r;
        }

        if (fchown(fdt, st->st_uid, st->st_gid) < 0)
                r = -errno;

        if (fchmod(fdt, st->st_mode & 07777) < 0)
                r = -errno;

        ts[0] = st->st_atim;
        ts[1] = st->st_mtim;
        (void) futimens(fdt, ts);

        (void) copy_xattr(fdf, fdt);

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

static int fd_copy_directory(
                int df,
                const char *from,
                const struct stat *st,
                int dt,
                const char *to,
                dev_t original_device,
                bool merge) {

        _cleanup_close_ int fdf = -1, fdt = -1;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        bool created;
        int r;

        assert(st);
        assert(to);

        if (from)
                fdf = openat(df, from, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        else
                fdf = fcntl(df, F_DUPFD_CLOEXEC, 3);

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
                struct timespec ut[2] = {
                        st->st_atim,
                        st->st_mtim
                };

                if (fchown(fdt, st->st_uid, st->st_gid) < 0)
                        r = -errno;

                if (fchmod(fdt, st->st_mode & 07777) < 0)
                        r = -errno;

                (void) futimens(fdt, ut);
                (void) copy_xattr(dirfd(d), fdt);
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                struct stat buf;
                int q;

                if (STR_IN_SET(de->d_name, ".", ".."))
                        continue;

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
                        q = -EOPNOTSUPP;

                if (q == -EEXIST && merge)
                        q = 0;

                if (q < 0)
                        r = q;
        }

        return r;
}

int copy_tree_at(int fdf, const char *from, int fdt, const char *to, bool merge) {
        struct stat st;

        assert(from);
        assert(to);

        if (fstatat(fdf, from, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        if (S_ISREG(st.st_mode))
                return fd_copy_regular(fdf, from, &st, fdt, to);
        else if (S_ISDIR(st.st_mode))
                return fd_copy_directory(fdf, from, &st, fdt, to, st.st_dev, merge);
        else if (S_ISLNK(st.st_mode))
                return fd_copy_symlink(fdf, from, &st, fdt, to);
        else if (S_ISFIFO(st.st_mode))
                return fd_copy_fifo(fdf, from, &st, fdt, to);
        else if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))
                return fd_copy_node(fdf, from, &st, fdt, to);
        else
                return -EOPNOTSUPP;
}

int copy_tree(const char *from, const char *to, bool merge) {
        return copy_tree_at(AT_FDCWD, from, AT_FDCWD, to, merge);
}

int copy_directory_fd(int dirfd, const char *to, bool merge) {

        struct stat st;

        assert(dirfd >= 0);
        assert(to);

        if (fstat(dirfd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;

        return fd_copy_directory(dirfd, NULL, &st, AT_FDCWD, to, st.st_dev, merge);
}

int copy_file_fd(const char *from, int fdt, bool try_reflink) {
        _cleanup_close_ int fdf = -1;
        int r;

        assert(from);
        assert(fdt >= 0);

        fdf = open(from, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fdf < 0)
                return -errno;

        r = copy_bytes(fdf, fdt, (off_t) -1, try_reflink);

        (void) copy_times(fdf, fdt);
        (void) copy_xattr(fdf, fdt);

        return r;
}

int copy_file(const char *from, const char *to, int flags, mode_t mode, unsigned chattr_flags) {
        int fdt = -1, r;

        assert(from);
        assert(to);

        RUN_WITH_UMASK(0000) {
                fdt = open(to, flags|O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, mode);
                if (fdt < 0)
                        return -errno;
        }

        if (chattr_flags != 0)
                (void) chattr_fd(fdt, chattr_flags, (unsigned) -1);

        r = copy_file_fd(from, fdt, true);
        if (r < 0) {
                close(fdt);
                unlink(to);
                return r;
        }

        if (close(fdt) < 0) {
                unlink_noerrno(to);
                return -errno;
        }

        return 0;
}

int copy_file_atomic(const char *from, const char *to, mode_t mode, bool replace, unsigned chattr_flags) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(from);
        assert(to);

        r = tempfn_random(to, NULL, &t);
        if (r < 0)
                return r;

        r = copy_file(from, t, O_NOFOLLOW|O_EXCL, mode, chattr_flags);
        if (r < 0)
                return r;

        if (replace) {
                r = renameat(AT_FDCWD, t, AT_FDCWD, to);
                if (r < 0)
                        r = -errno;
        } else
                r = rename_noreplace(AT_FDCWD, t, AT_FDCWD, to);
        if (r < 0) {
                (void) unlink_noerrno(t);
                return r;
        }

        return 0;
}

int copy_times(int fdf, int fdt) {
        struct timespec ut[2];
        struct stat st;
        usec_t crtime = 0;

        assert(fdf >= 0);
        assert(fdt >= 0);

        if (fstat(fdf, &st) < 0)
                return -errno;

        ut[0] = st.st_atim;
        ut[1] = st.st_mtim;

        if (futimens(fdt, ut) < 0)
                return -errno;

        if (fd_getcrtime(fdf, &crtime) >= 0)
                (void) fd_setcrtime(fdt, crtime);

        return 0;
}

int copy_xattr(int fdf, int fdt) {
        _cleanup_free_ char *bufa = NULL, *bufb = NULL;
        size_t sza = 100, szb = 100;
        ssize_t n;
        int ret = 0;
        const char *p;

        for (;;) {
                bufa = malloc(sza);
                if (!bufa)
                        return -ENOMEM;

                n = flistxattr(fdf, bufa, sza);
                if (n == 0)
                        return 0;
                if (n > 0)
                        break;
                if (errno != ERANGE)
                        return -errno;

                sza *= 2;

                bufa = mfree(bufa);
        }

        p = bufa;
        while (n > 0) {
                size_t l;

                l = strlen(p);
                assert(l < (size_t) n);

                if (startswith(p, "user.")) {
                        ssize_t m;

                        if (!bufb) {
                                bufb = malloc(szb);
                                if (!bufb)
                                        return -ENOMEM;
                        }

                        m = fgetxattr(fdf, p, bufb, szb);
                        if (m < 0) {
                                if (errno == ERANGE) {
                                        szb *= 2;
                                        bufb = mfree(bufb);
                                        continue;
                                }

                                return -errno;
                        }

                        if (fsetxattr(fdt, p, bufb, m, 0) < 0)
                                ret = -errno;
                }

                p += l + 1;
                n -= l + 1;
        }

        return ret;
}
