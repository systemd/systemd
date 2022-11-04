/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#if WANT_LINUX_FS_H
#include <linux/fs.h>
#endif
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "macro.h"
#include "missing_fcntl.h"
#include "missing_fs.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "tmpfile-util.h"
#include "util.h"

/* The maximum number of iterations in the loop to close descriptors in the fallback case
 * when /proc/self/fd/ is inaccessible. */
#define MAX_FD_LOOP_LIMIT (1024*1024)

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

void safe_close_pair(int p[static 2]) {
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
        assert(fds || n_fd <= 0);

        for (size_t i = 0; i < n_fd; i++)
                safe_close(fds[i]);
}

int fclose_nointr(FILE *f) {
        assert(f);

        /* Same as close_nointr(), but for fclose() */

        errno = 0; /* Extra safety: if the FILE* object is not encapsulating an fd, it might not set errno
                    * correctly. Let's hence initialize it to zero first, so that we aren't confused by any
                    * prior errno here */
        if (fclose(f) == 0)
                return 0;

        if (errno == EINTR)
                return 0;

        return errno_or_else(EIO);
}

FILE* safe_fclose(FILE *f) {

        /* Same as safe_close(), but for fclose() */

        if (f) {
                PROTECT_ERRNO;

                assert_se(fclose_nointr(f) != -EBADF);
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

        nflags = UPDATE_FLAG(flags, O_NONBLOCK, nonblock);
        if (nflags == flags)
                return 0;

        return RET_NERRNO(fcntl(fd, F_SETFL, nflags));
}

int fd_cloexec(int fd, bool cloexec) {
        int flags, nflags;

        assert(fd >= 0);

        flags = fcntl(fd, F_GETFD, 0);
        if (flags < 0)
                return -errno;

        nflags = UPDATE_FLAG(flags, FD_CLOEXEC, cloexec);
        if (nflags == flags)
                return 0;

        return RET_NERRNO(fcntl(fd, F_SETFD, nflags));
}

int fd_cloexec_many(const int fds[], size_t n_fds, bool cloexec) {
        int ret = 0, r;

        assert(n_fds == 0 || fds);

        for (size_t i = 0; i < n_fds; i++) {
                if (fds[i] < 0) /* Skip gracefully over already invalidated fds */
                        continue;

                r = fd_cloexec(fds[i], cloexec);
                if (r < 0 && ret >= 0) /* Continue going, but return first error */
                        ret = r;
                else
                        ret = 1; /* report if we did anything */
        }

        return ret;
}

_pure_ static bool fd_in_set(int fd, const int fdset[], size_t n_fdset) {
        assert(n_fdset == 0 || fdset);

        for (size_t i = 0; i < n_fdset; i++) {
                if (fdset[i] < 0)
                        continue;

                if (fdset[i] == fd)
                        return true;
        }

        return false;
}

int get_max_fd(void) {
        struct rlimit rl;
        rlim_t m;

        /* Return the highest possible fd, based RLIMIT_NOFILE, but enforcing FD_SETSIZE-1 as lower boundary
         * and INT_MAX as upper boundary. */

        if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
                return -errno;

        m = MAX(rl.rlim_cur, rl.rlim_max);
        if (m < FD_SETSIZE) /* Let's always cover at least 1024 fds */
                return FD_SETSIZE-1;

        if (m == RLIM_INFINITY || m > INT_MAX) /* Saturate on overflow. After all fds are "int", hence can
                                                * never be above INT_MAX */
                return INT_MAX;

        return (int) (m - 1);
}

static int close_all_fds_frugal(const int except[], size_t n_except) {
        int max_fd, r = 0;

        assert(n_except == 0 || except);

        /* This is the inner fallback core of close_all_fds(). This never calls malloc() or opendir() or so
         * and hence is safe to be called in signal handler context. Most users should call close_all_fds(),
         * but when we assume we are called from signal handler context, then use this simpler call
         * instead. */

        max_fd = get_max_fd();
        if (max_fd < 0)
                return max_fd;

        /* Refuse to do the loop over more too many elements. It's better to fail immediately than to
         * spin the CPU for a long time. */
        if (max_fd > MAX_FD_LOOP_LIMIT)
                return log_debug_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Refusing to loop over %d potential fds.",
                                       max_fd);

        for (int fd = 3; fd >= 0; fd = fd < max_fd ? fd + 1 : -1) {
                int q;

                if (fd_in_set(fd, except, n_except))
                        continue;

                q = close_nointr(fd);
                if (q < 0 && q != -EBADF && r >= 0)
                        r = q;
        }

        return r;
}

static bool have_close_range = true; /* Assume we live in the future */

static int close_all_fds_special_case(const int except[], size_t n_except) {
        assert(n_except == 0 || except);

        /* Handles a few common special cases separately, since they are common and can be optimized really
         * nicely, since we won't need sorting for them. Returns > 0 if the special casing worked, 0
         * otherwise. */

        if (!have_close_range)
                return 0;

        if (n_except == 1 && except[0] < 0) /* Minor optimization: if we only got one fd, and it's invalid,
                                             * we got none */
                n_except = 0;

        switch (n_except) {

        case 0:
                /* Close everything. Yay! */

                if (close_range(3, -1, 0) >= 0)
                        return 1;

                if (ERRNO_IS_NOT_SUPPORTED(errno) || ERRNO_IS_PRIVILEGE(errno)) {
                        have_close_range = false;
                        return 0;
                }

                return -errno;

        case 1:
                /* Close all but exactly one, then we don't need no sorting. This is a pretty common
                 * case, hence let's handle it specially. */

                if ((except[0] <= 3 || close_range(3, except[0]-1, 0) >= 0) &&
                    (except[0] >= INT_MAX || close_range(MAX(3, except[0]+1), -1, 0) >= 0))
                        return 1;

                if (ERRNO_IS_NOT_SUPPORTED(errno) || ERRNO_IS_PRIVILEGE(errno)) {
                        have_close_range = false;
                        return 0;
                }

                return -errno;

        default:
                return 0;
        }
}

int close_all_fds_without_malloc(const int except[], size_t n_except) {
        int r;

        assert(n_except == 0 || except);

        r = close_all_fds_special_case(except, n_except);
        if (r < 0)
                return r;
        if (r > 0) /* special case worked! */
                return 0;

        return close_all_fds_frugal(except, n_except);
}

int close_all_fds(const int except[], size_t n_except) {
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        assert(n_except == 0 || except);

        r = close_all_fds_special_case(except, n_except);
        if (r < 0)
                return r;
        if (r > 0) /* special case worked! */
                return 0;

        if (have_close_range) {
                _cleanup_free_ int *sorted_malloc = NULL;
                size_t n_sorted;
                int *sorted;

                /* In the best case we have close_range() to close all fds between a start and an end fd,
                 * which we can use on the "inverted" exception array, i.e. all intervals between all
                 * adjacent pairs from the sorted exception array. This changes loop complexity from O(n)
                 * where n is number of open fds to O(m⋅log(m)) where m is the number of fds to keep
                 * open. Given that we assume n ≫ m that's preferable to us. */

                assert(n_except < SIZE_MAX);
                n_sorted = n_except + 1;

                if (n_sorted > 64) /* Use heap for large numbers of fds, stack otherwise */
                        sorted = sorted_malloc = new(int, n_sorted);
                else
                        sorted = newa(int, n_sorted);

                if (sorted) {
                        memcpy(sorted, except, n_except * sizeof(int));

                        /* Let's add fd 2 to the list of fds, to simplify the loop below, as this
                         * allows us to cover the head of the array the same way as the body */
                        sorted[n_sorted-1] = 2;

                        typesafe_qsort(sorted, n_sorted, cmp_int);

                        for (size_t i = 0; i < n_sorted-1; i++) {
                                int start, end;

                                start = MAX(sorted[i], 2); /* The first three fds shall always remain open */
                                end = MAX(sorted[i+1], 2);

                                assert(end >= start);

                                if (end - start <= 1)
                                        continue;

                                /* Close everything between the start and end fds (both of which shall stay open) */
                                if (close_range(start + 1, end - 1, 0) < 0) {
                                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                                                return -errno;

                                        have_close_range = false;
                                        break;
                                }
                        }

                        if (have_close_range) {
                                /* The loop succeeded. Let's now close everything beyond the end */

                                if (sorted[n_sorted-1] >= INT_MAX) /* Dont let the addition below overflow */
                                        return 0;

                                if (close_range(sorted[n_sorted-1] + 1, -1, 0) >= 0)
                                        return 0;

                                if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                                        return -errno;

                                have_close_range = false;
                        }
                }

                /* Fallback on OOM or if close_range() is not supported */
        }

        d = opendir("/proc/self/fd");
        if (!d)
                return close_all_fds_frugal(except, n_except); /* ultimate fallback if /proc/ is not available */

        FOREACH_DIRENT(de, d, return -errno) {
                int fd = -1, q;

                if (!IN_SET(de->d_type, DT_LNK, DT_UNKNOWN))
                        continue;

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

        /* Compares two file descriptors. Note that semantics are quite different depending on whether we
         * have kcmp() or we don't. If we have kcmp() this will only return true for dup()ed file
         * descriptors, but not otherwise. If we don't have kcmp() this will also return true for two fds of
         * the same file, created by separate open() calls. Since we use this call mostly for filtering out
         * duplicates in the fd store this difference hopefully doesn't matter too much. */

        if (a == b)
                return true;

        /* Try to use kcmp() if we have it. */
        pid = getpid_cached();
        r = kcmp(pid, pid, KCMP_FILE, a, b);
        if (r == 0)
                return true;
        if (r > 0)
                return false;
        if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                return -errno;

        /* We don't have kcmp(), use fstat() instead. */
        if (fstat(a, &sta) < 0)
                return -errno;

        if (fstat(b, &stb) < 0)
                return -errno;

        if (!stat_inode_same(&sta, &stb))
                return false;

        /* We consider all device fds different, since two device fds might refer to quite different device
         * contexts even though they share the same inode and backing dev_t. */

        if (S_ISCHR(sta.st_mode) || S_ISBLK(sta.st_mode))
                return false;

        /* The fds refer to the same inode on disk, let's also check if they have the same fd flags. This is
         * useful to distinguish the read and write side of a pipe created with pipe(). */
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

        return p - s <= FDNAME_MAX;
}

int fd_get_path(int fd, char **ret) {
        int r;

        r = readlink_malloc(FORMAT_PROC_FD_PATH(fd), ret);
        if (r == -ENOENT) {
                /* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's make
                 * things debuggable and distinguish the two. */

                if (proc_mounted() == 0)
                        return -ENOSYS;  /* /proc is not available or not set up properly, we're most likely in some chroot
                                          * environment. */
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

                        close_and_replace(null_fd, copy);
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
        int new_fd, r;

        /* Reopens the specified fd with new flags. This is useful for convert an O_PATH fd into a regular one, or to
         * turn O_RDWR fds into O_RDONLY fds.
         *
         * This doesn't work on sockets (since they cannot be open()ed, ever).
         *
         * This implicitly resets the file read index to 0. */

        if (FLAGS_SET(flags, O_DIRECTORY)) {
                /* If we shall reopen the fd as directory we can just go via "." and thus bypass the whole
                 * magic /proc/ directory, and make ourselves independent of that being mounted. */
                new_fd = openat(fd, ".", flags);
                if (new_fd < 0)
                        return -errno;

                return new_fd;
        }

        new_fd = open(FORMAT_PROC_FD_PATH(fd), flags);
        if (new_fd < 0) {
                if (errno != ENOENT)
                        return -errno;

                r = proc_mounted();
                if (r == 0)
                        return -ENOSYS; /* if we have no /proc/, the concept is not implementable */

                return r > 0 ? -EBADF : -ENOENT; /* If /proc/ is definitely around then this means the fd is
                                                  * not valid, otherwise let's propagate the original
                                                  * error */
        }

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

        /* If we fail, fall back to the hard-coded kernel limit of 1024 * 1024. */
        return 1024 * 1024;
}

int fd_get_diskseq(int fd, uint64_t *ret) {
        uint64_t diskseq;

        assert(fd >= 0);
        assert(ret);

        if (ioctl(fd, BLKGETDISKSEQ, &diskseq) < 0) {
                /* Note that the kernel is weird: non-existing ioctls currently return EINVAL
                 * rather than ENOTTY on loopback block devices. They should fix that in the kernel,
                 * but in the meantime we accept both here. */
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EINVAL)
                        return -errno;

                return -EOPNOTSUPP;
        }

        *ret = diskseq;

        return 0;
}
