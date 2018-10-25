/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "copy.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
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

void close_many(const int fds[], size_t n_fd) {
        size_t i;

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

_pure_ static bool fd_in_set(int fd, const int fdset[], size_t n_fdset) {
        size_t i;

        assert(n_fdset == 0 || fdset);

        for (i = 0; i < n_fdset; i++)
                if (fdset[i] == fd)
                        return true;

        return false;
}

int close_all_fds(const int except[], size_t n_except) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(n_except == 0 || except);

        d = opendir("/proc/self/fd");
        if (!d) {
                struct rlimit rl;
                int fd, max_fd;

                /* When /proc isn't available (for example in chroots) the fallback is brute forcing through the fd
                 * table */

                assert_se(getrlimit(RLIMIT_NOFILE, &rl) >= 0);

                if (rl.rlim_max == 0)
                        return -EINVAL;

                /* Let's take special care if the resource limit is set to unlimited, or actually larger than the range
                 * of 'int'. Let's avoid implicit overflows. */
                max_fd = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > INT_MAX) ? INT_MAX : (int) (rl.rlim_max - 1);

                for (fd = 3; fd >= 0; fd = fd < max_fd ? fd + 1 : -1) {
                        int q;

                        if (fd_in_set(fd, except, n_except))
                                continue;

                        q = close_nointr(fd);
                        if (q < 0 && q != -EBADF && r >= 0)
                                r = q;
                }

                return r;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                int fd = -1, q;

                if (safe_atoi(de->d_name, &fd) < 0)
                        /* Let's better ignore this, just in case */
                        continue;

                if (fd < 3)
                        continue;

                if (fd == dirfd(d))
                        continue;

                if (fd_in_set(fd, except, n_except))
                        continue;

                q = close_nointr(fd);
                if (q < 0 && q != -EBADF && r >= 0) /* Valgrind has its own FD and doesn't want to have it closed */
                        r = q;
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
        if (!IN_SET(errno, ENOSYS, EACCES, EPERM))
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
        if (r == -ENOENT) {
                /* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's make
                 * things debuggable and distuingish the two. */

                if (access("/proc/self/fd/", F_OK) < 0)
                        /* /proc is not available or not set up properly, we're most likely in some chroot
                         * environment. */
                        return errno == ENOENT ? -EOPNOTSUPP : -errno;

                return -EBADF; /* The directory exists, hence it's the fd that doesn't. */
        }

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

                return TAKE_FD(fd);
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

                return TAKE_FD(pipefds[0]);
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
                return fd_reopen(fd, O_RDONLY|O_CLOEXEC);
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

/* When the data is smaller or equal to 64K, try to place the copy in a memfd/pipe */
#define DATA_FD_MEMORY_LIMIT (64U*1024U)

/* If memfd/pipe didn't work out, then let's use a file in /tmp up to a size of 1M. If it's large than that use /var/tmp instead. */
#define DATA_FD_TMP_LIMIT (1024U*1024U)

int fd_duplicate_data_fd(int fd) {

        _cleanup_close_ int copy_fd = -1, tmp_fd = -1;
        _cleanup_free_ void *remains = NULL;
        size_t remains_size = 0;
        const char *td;
        struct stat st;
        int r;

        /* Creates a 'data' fd from the specified source fd, containing all the same data in a read-only fashion, but
         * independent of it (i.e. the source fd can be closed and unmounted after this call succeeded). Tries to be
         * somewhat smart about where to place the data. In the best case uses a memfd(). If memfd() are not supported
         * uses a pipe instead. For larger data will use an unlinked file in /tmp, and for even larger data one in
         * /var/tmp. */

        if (fstat(fd, &st) < 0)
                return -errno;

        /* For now, let's only accept regular files, sockets, pipes and char devices */
        if (S_ISDIR(st.st_mode))
                return -EISDIR;
        if (S_ISLNK(st.st_mode))
                return -ELOOP;
        if (!S_ISREG(st.st_mode) && !S_ISSOCK(st.st_mode) && !S_ISFIFO(st.st_mode) && !S_ISCHR(st.st_mode))
                return -EBADFD;

        /* If we have reason to believe the data is bounded in size, then let's use memfds or pipes as backing fd. Note
         * that we use the reported regular file size only as a hint, given that there are plenty special files in
         * /proc and /sys which report a zero file size but can be read from. */

        if (!S_ISREG(st.st_mode) || st.st_size < DATA_FD_MEMORY_LIMIT) {

                /* Try a memfd first */
                copy_fd = memfd_new("data-fd");
                if (copy_fd >= 0) {
                        off_t f;

                        r = copy_bytes(fd, copy_fd, DATA_FD_MEMORY_LIMIT, 0);
                        if (r < 0)
                                return r;

                        f = lseek(copy_fd, 0, SEEK_SET);
                        if (f != 0)
                                return -errno;

                        if (r == 0) {
                                /* Did it fit into the limit? If so, we are done. */
                                r = memfd_set_sealed(copy_fd);
                                if (r < 0)
                                        return r;

                                return TAKE_FD(copy_fd);
                        }

                        /* Hmm, pity, this didn't fit. Let's fall back to /tmp then, see below */

                } else {
                        _cleanup_(close_pairp) int pipefds[2] = { -1, -1 };
                        int isz;

                        /* If memfds aren't available, use a pipe. Set O_NONBLOCK so that we will get EAGAIN rather
                         * then block indefinitely when we hit the pipe size limit */

                        if (pipe2(pipefds, O_CLOEXEC|O_NONBLOCK) < 0)
                                return -errno;

                        isz = fcntl(pipefds[1], F_GETPIPE_SZ, 0);
                        if (isz < 0)
                                return -errno;

                        /* Try to enlarge the pipe size if necessary */
                        if ((size_t) isz < DATA_FD_MEMORY_LIMIT) {

                                (void) fcntl(pipefds[1], F_SETPIPE_SZ, DATA_FD_MEMORY_LIMIT);

                                isz = fcntl(pipefds[1], F_GETPIPE_SZ, 0);
                                if (isz < 0)
                                        return -errno;
                        }

                        if ((size_t) isz >= DATA_FD_MEMORY_LIMIT) {

                                r = copy_bytes_full(fd, pipefds[1], DATA_FD_MEMORY_LIMIT, 0, &remains, &remains_size);
                                if (r < 0 && r != -EAGAIN)
                                        return r; /* If we get EAGAIN it could be because of the source or because of
                                                   * the destination fd, we can't know, as sendfile() and friends won't
                                                   * tell us. Hence, treat this as reason to fall back, just to be
                                                   * sure. */
                                if (r == 0) {
                                        /* Everything fit in, yay! */
                                        (void) fd_nonblock(pipefds[0], false);

                                        return TAKE_FD(pipefds[0]);
                                }

                                /* Things didn't fit in. But we read data into the pipe, let's remember that, so that
                                 * when writing the new file we incorporate this first. */
                                copy_fd = TAKE_FD(pipefds[0]);
                        }
                }
        }

        /* If we have reason to believe this will fit fine in /tmp, then use that as first fallback. */
        if ((!S_ISREG(st.st_mode) || st.st_size < DATA_FD_TMP_LIMIT) &&
            (DATA_FD_MEMORY_LIMIT + remains_size) < DATA_FD_TMP_LIMIT) {
                off_t f;

                tmp_fd = open_tmpfile_unlinkable(NULL /* NULL as directory means /tmp */, O_RDWR|O_CLOEXEC);
                if (tmp_fd < 0)
                        return tmp_fd;

                if (copy_fd >= 0) {
                        /* If we tried a memfd/pipe first and it ended up being too large, then copy this into the
                         * temporary file first. */

                        r = copy_bytes(copy_fd, tmp_fd, UINT64_MAX, 0);
                        if (r < 0)
                                return r;

                        assert(r == 0);
                }

                if (remains_size > 0) {
                        /* If there were remaining bytes (i.e. read into memory, but not written out yet) from the
                         * failed copy operation, let's flush them out next. */

                        r = loop_write(tmp_fd, remains, remains_size, false);
                        if (r < 0)
                                return r;
                }

                r = copy_bytes(fd, tmp_fd, DATA_FD_TMP_LIMIT - DATA_FD_MEMORY_LIMIT - remains_size, COPY_REFLINK);
                if (r < 0)
                        return r;
                if (r == 0)
                        goto finish;  /* Yay, it fit in */

                /* It didn't fit in. Let's not forget to use what we already used */
                f = lseek(tmp_fd, 0, SEEK_SET);
                if (f != 0)
                        return -errno;

                safe_close(copy_fd);
                copy_fd = TAKE_FD(tmp_fd);

                remains = mfree(remains);
                remains_size = 0;
        }

        /* As last fallback use /var/tmp */
        r = var_tmp_dir(&td);
        if (r < 0)
                return r;

        tmp_fd = open_tmpfile_unlinkable(td, O_RDWR|O_CLOEXEC);
        if (tmp_fd < 0)
                return tmp_fd;

        if (copy_fd >= 0) {
                /* If we tried a memfd/pipe first, or a file in /tmp, and it ended up being too large, than copy this
                 * into the temporary file first. */
                r = copy_bytes(copy_fd, tmp_fd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return r;

                assert(r == 0);
        }

        if (remains_size > 0) {
                /* Then, copy in any read but not yet written bytes. */
                r = loop_write(tmp_fd, remains, remains_size, false);
                if (r < 0)
                        return r;
        }

        /* Copy in the rest */
        r = copy_bytes(fd, tmp_fd, UINT64_MAX, COPY_REFLINK);
        if (r < 0)
                return r;

        assert(r == 0);

finish:
        /* Now convert the O_RDWR file descriptor into an O_RDONLY one (and as side effect seek to the beginning of the
         * file again */

        return fd_reopen(tmp_fd, O_RDONLY|O_CLOEXEC);
}

int fd_move_above_stdio(int fd) {
        int flags, copy;
        PROTECT_ERRNO;

        /* Moves the specified file descriptor if possible out of the range [0…2], i.e. the range of
         * stdin/stdout/stderr. If it can't be moved outside of this range the original file descriptor is
         * returned. This call is supposed to be used for long-lasting file descriptors we allocate in our code that
         * might get loaded into foreign code, and where we want ensure our fds are unlikely used accidentally as
         * stdin/stdout/stderr of unrelated code.
         *
         * Note that this doesn't fix any real bugs, it just makes it less likely that our code will be affected by
         * buggy code from others that mindlessly invokes 'fprintf(stderr, …' or similar in places where stderr has
         * been closed before.
         *
         * This function is written in a "best-effort" and "least-impact" style. This means whenever we encounter an
         * error we simply return the original file descriptor, and we do not touch errno. */

        if (fd < 0 || fd > 2)
                return fd;

        flags = fcntl(fd, F_GETFD, 0);
        if (flags < 0)
                return fd;

        if (flags & FD_CLOEXEC)
                copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        else
                copy = fcntl(fd, F_DUPFD, 3);
        if (copy < 0)
                return fd;

        assert(copy > 2);

        (void) close(fd);
        return copy;
}

int rearrange_stdio(int original_input_fd, int original_output_fd, int original_error_fd) {

        int fd[3] = { /* Put together an array of fds we work on */
                original_input_fd,
                original_output_fd,
                original_error_fd
        };

        int r, i,
                null_fd = -1,                /* if we open /dev/null, we store the fd to it here */
                copy_fd[3] = { -1, -1, -1 }; /* This contains all fds we duplicate here temporarily, and hence need to close at the end */
        bool null_readable, null_writable;

        /* Sets up stdin, stdout, stderr with the three file descriptors passed in. If any of the descriptors is
         * specified as -1 it will be connected with /dev/null instead. If any of the file descriptors is passed as
         * itself (e.g. stdin as STDIN_FILENO) it is left unmodified, but the O_CLOEXEC bit is turned off should it be
         * on.
         *
         * Note that if any of the passed file descriptors are > 2 they will be closed — both on success and on
         * failure! Thus, callers should assume that when this function returns the input fds are invalidated.
         *
         * Note that when this function fails stdin/stdout/stderr might remain half set up!
         *
         * O_CLOEXEC is turned off for all three file descriptors (which is how it should be for
         * stdin/stdout/stderr). */

        null_readable = original_input_fd < 0;
        null_writable = original_output_fd < 0 || original_error_fd < 0;

        /* First step, open /dev/null once, if we need it */
        if (null_readable || null_writable) {

                /* Let's open this with O_CLOEXEC first, and convert it to non-O_CLOEXEC when we move the fd to the final position. */
                null_fd = open("/dev/null", (null_readable && null_writable ? O_RDWR :
                                             null_readable ? O_RDONLY : O_WRONLY) | O_CLOEXEC);
                if (null_fd < 0) {
                        r = -errno;
                        goto finish;
                }

                /* If this fd is in the 0…2 range, let's move it out of it */
                if (null_fd < 3) {
                        int copy;

                        copy = fcntl(null_fd, F_DUPFD_CLOEXEC, 3); /* Duplicate this with O_CLOEXEC set */
                        if (copy < 0) {
                                r = -errno;
                                goto finish;
                        }

                        safe_close(null_fd);
                        null_fd = copy;
                }
        }

        /* Let's assemble fd[] with the fds to install in place of stdin/stdout/stderr */
        for (i = 0; i < 3; i++) {

                if (fd[i] < 0)
                        fd[i] = null_fd;        /* A negative parameter means: connect this one to /dev/null */
                else if (fd[i] != i && fd[i] < 3) {
                        /* This fd is in the 0…2 territory, but not at its intended place, move it out of there, so that we can work there. */
                        copy_fd[i] = fcntl(fd[i], F_DUPFD_CLOEXEC, 3); /* Duplicate this with O_CLOEXEC set */
                        if (copy_fd[i] < 0) {
                                r = -errno;
                                goto finish;
                        }

                        fd[i] = copy_fd[i];
                }
        }

        /* At this point we now have the fds to use in fd[], and they are all above the stdio range, so that we
         * have freedom to move them around. If the fds already were at the right places then the specific fds are
         * -1. Let's now move them to the right places. This is the point of no return. */
        for (i = 0; i < 3; i++) {

                if (fd[i] == i) {

                        /* fd is already in place, but let's make sure O_CLOEXEC is off */
                        r = fd_cloexec(i, false);
                        if (r < 0)
                                goto finish;

                } else {
                        assert(fd[i] > 2);

                        if (dup2(fd[i], i) < 0) { /* Turns off O_CLOEXEC on the new fd. */
                                r = -errno;
                                goto finish;
                        }
                }
        }

        r = 0;

finish:
        /* Close the original fds, but only if they were outside of the stdio range. Also, properly check for the same
         * fd passed in multiple times. */
        safe_close_above_stdio(original_input_fd);
        if (original_output_fd != original_input_fd)
                safe_close_above_stdio(original_output_fd);
        if (original_error_fd != original_input_fd && original_error_fd != original_output_fd)
                safe_close_above_stdio(original_error_fd);

        /* Close the copies we moved > 2 */
        for (i = 0; i < 3; i++)
                safe_close(copy_fd[i]);

        /* Close our null fd, if it's > 2 */
        safe_close_above_stdio(null_fd);

        return r;
}

int fd_reopen(int fd, int flags) {
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        int new_fd;

        /* Reopens the specified fd with new flags. This is useful for convert an O_PATH fd into a regular one, or to
         * turn O_RDWR fds into O_RDONLY fds.
         *
         * This doesn't work on sockets (since they cannot be open()ed, ever).
         *
         * This implicitly resets the file read index to 0. */

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);
        new_fd = open(procfs_path, flags);
        if (new_fd < 0)
                return -errno;

        return new_fd;
}

int read_nr_open(void) {
        _cleanup_free_ char *nr_open = NULL;
        int r;

        /* Returns the kernel's current fd limit, either by reading it of /proc/sys if that works, or using the
         * hard-coded default compiled-in value of current kernels (1M) if not. This call will never fail. */

        r = read_one_line_file("/proc/sys/fs/nr_open", &nr_open);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/sys/fs/nr_open, ignoring: %m");
        else {
                int v;

                r = safe_atoi(nr_open, &v);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse /proc/sys/fs/nr_open value '%s', ignoring: %m", nr_open);
                else
                        return v;
        }

        /* If we fail, fallback to the hard-coded kernel limit of 1024 * 1024. */
        return 1024 * 1024;
}
