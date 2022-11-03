/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "copy.h"
#include "data-fd-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "memfd-util.h"
#include "tmpfile-util.h"

/* When the data is smaller or equal to 64K, try to place the copy in a memfd/pipe */
#define DATA_FD_MEMORY_LIMIT (64U*1024U)

/* If memfd/pipe didn't work out, then let's use a file in /tmp up to a size of 1M. If it's large than that use /var/tmp instead. */
#define DATA_FD_TMP_LIMIT (1024U*1024U)

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

        if (size == 0 && ((flags & ACQUIRE_NO_DEV_NULL) == 0))
                /* As a special case, return /dev/null if we have been called for an empty data block */
                return RET_NERRNO(open("/dev/null", O_RDONLY|O_CLOEXEC|O_NOCTTY));

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

int copy_data_fd(int fd) {
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

                                r = copy_bytes_full(fd, pipefds[1], DATA_FD_MEMORY_LIMIT, 0, &remains, &remains_size, NULL, NULL);
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

                close_and_replace(copy_fd, tmp_fd);

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
