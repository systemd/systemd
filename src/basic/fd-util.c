/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "memfd-util.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "util.h"

int close_nointr(int fd) {
        assert(fd >= 0);

        if (close(fd) >= 0)
                return 0;

        /*
         * Just ignore EINTR; a retry loop is the wrong thing to do on
         * Linux.
         *
         * http://lkml.indiana.edu/hypermail/linux/kernel/0509.1/0877.html
         * https://bugzilla.gnome.org/show_bug.cgi?id=682819
         * http://utcc.utoronto.ca/~cks/space/blog/unix/CloseEINTR
         * https://sites.google.com/site/michaelsafyan/software-engineering/checkforeintrwheninvokingclosethinkagain
         */
        if (errno == EINTR)
                return 0;

        return -errno;
}

int safe_close(int fd) {

        /*
         * Like close_nointr() but cannot fail. Guarantees errno is
         * unchanged. Is a NOP with negative fds passed, and returns
         * -1, so that it can be used in this syntax:
         *
         * fd = safe_close(fd);
         */

        if (fd >= 0) {
                PROTECT_ERRNO;

                /* The kernel might return pretty much any error code
                 * via close(), but the fd will be closed anyway. The
                 * only condition we want to check for here is whether
                 * the fd was invalid at all... */

                assert_se(close_nointr(fd) != -EBADF);
        }

        return -1;
}

void safe_close_pair(int p[]) {
        assert(p);

        if (p[0] == p[1]) {
                /* Special case pairs which use the same fd in both
                 * directions... */
                p[0] = p[1] = safe_close(p[0]);
                return;
        }

        p[0] = safe_close(p[0]);
        p[1] = safe_close(p[1]);
}

void close_many(const int fds[], unsigned n_fd) {
        unsigned i;

        assert(fds || n_fd <= 0);

        for (i = 0; i < n_fd; i++)
                safe_close(fds[i]);
}

int fclose_nointr(FILE *f) {
        assert(f);

        /* Same as close_nointr(), but for fclose() */

        if (fclose(f) == 0)
                return 0;

        if (errno == EINTR)
                return 0;

        return -errno;
}

FILE* safe_fclose(FILE *f) {

        /* Same as safe_close(), but for fclose() */

        if (f) {
                PROTECT_ERRNO;

                assert_se(fclose_nointr(f) != EBADF);
        }

        return NULL;
}

DIR* safe_closedir(DIR *d) {

        if (d) {
                PROTECT_ERRNO;

                assert_se(closedir(d) >= 0 || errno != EBADF);
        }

        return NULL;
}

int fd_nonblock(int fd, bool nonblock) {
        int flags, nflags;

        assert(fd >= 0);

        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0)
                return -errno;

        if (nonblock)
                nflags = flags | O_NONBLOCK;
        else
                nflags = flags & ~O_NONBLOCK;

        if (nflags == flags)
                return 0;

        if (fcntl(fd, F_SETFL, nflags) < 0)
                return -errno;

        return 0;
}

int fd_cloexec(int fd, bool cloexec) {
        int flags, nflags;

        assert(fd >= 0);

        flags = fcntl(fd, F_GETFD, 0);
        if (flags < 0)
                return -errno;

        if (cloexec)
                nflags = flags | FD_CLOEXEC;
        else
                nflags = flags & ~FD_CLOEXEC;

        if (nflags == flags)
                return 0;

        if (fcntl(fd, F_SETFD, nflags) < 0)
                return -errno;

        return 0;
}

void stdio_unset_cloexec(void) {
        fd_cloexec(STDIN_FILENO, false);
        fd_cloexec(STDOUT_FILENO, false);
        fd_cloexec(STDERR_FILENO, false);
}

_pure_ static bool fd_in_set(int fd, const int fdset[], unsigned n_fdset) {
        unsigned i;

        assert(n_fdset == 0 || fdset);

        for (i = 0; i < n_fdset; i++)
                if (fdset[i] == fd)
                        return true;

        return false;
}

int close_all_fds(const int except[], unsigned n_except) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(n_except == 0 || except);

        d = opendir("/proc/self/fd");
        if (!d) {
                int fd;
                struct rlimit rl;

                /* When /proc isn't available (for example in chroots)
                 * the fallback is brute forcing through the fd
                 * table */

                assert_se(getrlimit(RLIMIT_NOFILE, &rl) >= 0);
                for (fd = 3; fd < (int) rl.rlim_max; fd ++) {

                        if (fd_in_set(fd, except, n_except))
                                continue;

                        if (close_nointr(fd) < 0)
                                if (errno != EBADF && r == 0)
                                        r = -errno;
                }

                return r;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                int fd = -1;

                if (safe_atoi(de->d_name, &fd) < 0)
                        /* Let's better ignore this, just in case */
                        continue;

                if (fd < 3)
                        continue;

                if (fd == dirfd(d))
                        continue;

                if (fd_in_set(fd, except, n_except))
                        continue;

                if (close_nointr(fd) < 0) {
                        /* Valgrind has its own FD and doesn't want to have it closed */
                        if (errno != EBADF && r == 0)
                                r = -errno;
                }
        }

        return r;
}

int same_fd(int a, int b) {
        struct stat sta, stb;
        pid_t pid;
        int r, fa, fb;

        assert(a >= 0);
        assert(b >= 0);

        /* Compares two file descriptors. Note that semantics are
         * quite different depending on whether we have kcmp() or we
         * don't. If we have kcmp() this will only return true for
         * dup()ed file descriptors, but not otherwise. If we don't
         * have kcmp() this will also return true for two fds of the same
         * file, created by separate open() calls. Since we use this
         * call mostly for filtering out duplicates in the fd store
         * this difference hopefully doesn't matter too much. */

        if (a == b)
                return true;

        /* Try to use kcmp() if we have it. */
        pid = getpid_cached();
        r = kcmp(pid, pid, KCMP_FILE, a, b);
        if (r == 0)
                return true;
        if (r > 0)
                return false;
        if (errno != ENOSYS)
                return -errno;

        /* We don't have kcmp(), use fstat() instead. */
        if (fstat(a, &sta) < 0)
                return -errno;

        if (fstat(b, &stb) < 0)
                return -errno;

        if ((sta.st_mode & S_IFMT) != (stb.st_mode & S_IFMT))
                return false;

        /* We consider all device fds different, since two device fds
         * might refer to quite different device contexts even though
         * they share the same inode and backing dev_t. */

        if (S_ISCHR(sta.st_mode) || S_ISBLK(sta.st_mode))
                return false;

        if (sta.st_dev != stb.st_dev || sta.st_ino != stb.st_ino)
                return false;

        /* The fds refer to the same inode on disk, let's also check
         * if they have the same fd flags. This is useful to
         * distinguish the read and write side of a pipe created with
         * pipe(). */
        fa = fcntl(a, F_GETFL);
        if (fa < 0)
                return -errno;

        fb = fcntl(b, F_GETFL);
        if (fb < 0)
                return -errno;

        return fa == fb;
}

void cmsg_close_all(struct msghdr *mh) {
        struct cmsghdr *cmsg;

        assert(mh);

        CMSG_FOREACH(cmsg, mh)
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
                        close_many((int*) CMSG_DATA(cmsg), (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
}

bool fdname_is_valid(const char *s) {
        const char *p;

        /* Validates a name for $LISTEN_FDNAMES. We basically allow
         * everything ASCII that's not a control character. Also, as
         * special exception the ":" character is not allowed, as we
         * use that as field separator in $LISTEN_FDNAMES.
         *
         * Note that the empty string is explicitly allowed
         * here. However, we limit the length of the names to 255
         * characters. */

        if (!s)
                return false;

        for (p = s; *p; p++) {
                if (*p < ' ')
                        return false;
                if (*p >= 127)
                        return false;
                if (*p == ':')
                        return false;
        }

        return p - s < 256;
}

int fd_get_path(int fd, char **ret) {
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        int r;

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);

        r = readlink_malloc(procfs_path, ret);

        if (r == -ENOENT) /* If the file doesn't exist the fd is invalid */
                return -EBADF;

        return r;
}

int move_fd(int from, int to, int cloexec) {
        int r;

        /* Move fd 'from' to 'to', make sure FD_CLOEXEC remains equal if requested, and release the old fd. If
         * 'cloexec' is passed as -1, the original FD_CLOEXEC is inherited for the new fd. If it is 0, it is turned
         * off, if it is > 0 it is turned on. */

        if (from < 0)
                return -EBADF;
        if (to < 0)
                return -EBADF;

        if (from == to) {

                if (cloexec >= 0) {
                        r = fd_cloexec(to, cloexec);
                        if (r < 0)
                                return r;
                }

                return to;
        }

        if (cloexec < 0) {
                int fl;

                fl = fcntl(from, F_GETFD, 0);
                if (fl < 0)
                        return -errno;

                cloexec = !!(fl & FD_CLOEXEC);
        }

        r = dup3(from, to, cloexec ? O_CLOEXEC : 0);
        if (r < 0)
                return -errno;

        assert(r == to);

        safe_close(from);

        return to;
}

int acquire_data_fd(const void *data, size_t size, unsigned flags) {

        char procfs_path[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        _cleanup_close_pair_ int pipefds[2] = { -1, -1 };
        char pattern[] = "/dev/shm/data-fd-XXXXXX";
        _cleanup_close_ int fd = -1;
        int isz = 0, r;
        ssize_t n;
        off_t f;

        assert(data || size == 0);

        /* Acquire a read-only file descriptor that when read from returns the specified data. This is much more
         * complex than I wish it was. But here's why:
         *
         * a) First we try to use memfds. They are the best option, as we can seal them nicely to make them
         *    read-only. Unfortunately they require kernel 3.17, and – at the time of writing – we still support 3.14.
         *
         * b) Then, we try classic pipes. They are the second best options, as we can close the writing side, retaining
         *    a nicely read-only fd in the reading side. However, they are by default quite small, and unprivileged
         *    clients can only bump their size to a system-wide limit, which might be quite low.
         *
         * c) Then, we try an O_TMPFILE file in /dev/shm (that dir is the only suitable one known to exist from
         *    earliest boot on). To make it read-only we open the fd a second time with O_RDONLY via
         *    /proc/self/<fd>. Unfortunately O_TMPFILE is not available on older kernels on tmpfs.
         *
         * d) Finally, we try creating a regular file in /dev/shm, which we then delete.
         *
         * It sucks a bit that depending on the situation we return very different objects here, but that's Linux I
         * figure. */

        if (size == 0 && ((flags & ACQUIRE_NO_DEV_NULL) == 0)) {
                /* As a special case, return /dev/null if we have been called for an empty data block */
                r = open("/dev/null", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (r < 0)
                        return -errno;

                return r;
        }

        if ((flags & ACQUIRE_NO_MEMFD) == 0) {
                fd = memfd_new("data-fd");
                if (fd < 0)
                        goto try_pipe;

                n = write(fd, data, size);
                if (n < 0)
                        return -errno;
                if ((size_t) n != size)
                        return -EIO;

                f = lseek(fd, 0, SEEK_SET);
                if (f != 0)
                        return -errno;

                r = memfd_set_sealed(fd);
                if (r < 0)
                        return r;

                r = fd;
                fd = -1;

                return r;
        }

try_pipe:
        if ((flags & ACQUIRE_NO_PIPE) == 0) {
                if (pipe2(pipefds, O_CLOEXEC|O_NONBLOCK) < 0)
                        return -errno;

                isz = fcntl(pipefds[1], F_GETPIPE_SZ, 0);
                if (isz < 0)
                        return -errno;

                if ((size_t) isz < size) {
                        isz = (int) size;
                        if (isz < 0 || (size_t) isz != size)
                                return -E2BIG;

                        /* Try to bump the pipe size */
                        (void) fcntl(pipefds[1], F_SETPIPE_SZ, isz);

                        /* See if that worked */
                        isz = fcntl(pipefds[1], F_GETPIPE_SZ, 0);
                        if (isz < 0)
                                return -errno;

                        if ((size_t) isz < size)
                                goto try_dev_shm;
                }

                n = write(pipefds[1], data, size);
                if (n < 0)
                        return -errno;
                if ((size_t) n != size)
                        return -EIO;

                (void) fd_nonblock(pipefds[0], false);

                r = pipefds[0];
                pipefds[0] = -1;

                return r;
        }

try_dev_shm:
        if ((flags & ACQUIRE_NO_TMPFILE) == 0) {
                fd = open("/dev/shm", O_RDWR|O_TMPFILE|O_CLOEXEC, 0500);
                if (fd < 0)
                        goto try_dev_shm_without_o_tmpfile;

                n = write(fd, data, size);
                if (n < 0)
                        return -errno;
                if ((size_t) n != size)
                        return -EIO;

                /* Let's reopen the thing, in order to get an O_RDONLY fd for the original O_RDWR one */
                xsprintf(procfs_path, "/proc/self/fd/%i", fd);
                r = open(procfs_path, O_RDONLY|O_CLOEXEC);
                if (r < 0)
                        return -errno;

                return r;
        }

try_dev_shm_without_o_tmpfile:
        if ((flags & ACQUIRE_NO_REGULAR) == 0) {
                fd = mkostemp_safe(pattern);
                if (fd < 0)
                        return fd;

                n = write(fd, data, size);
                if (n < 0) {
                        r = -errno;
                        goto unlink_and_return;
                }
                if ((size_t) n != size) {
                        r = -EIO;
                        goto unlink_and_return;
                }

                /* Let's reopen the thing, in order to get an O_RDONLY fd for the original O_RDWR one */
                r = open(pattern, O_RDONLY|O_CLOEXEC);
                if (r < 0)
                        r = -errno;

        unlink_and_return:
                (void) unlink(pattern);
                return r;
        }

        return -EOPNOTSUPP;
}
