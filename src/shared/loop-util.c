/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/blkpg.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "loop-util.h"
#include "parse-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"

static void cleanup_clear_loop_close(int *fd) {
        if (*fd >= 0) {
                (void) ioctl(*fd, LOOP_CLR_FD);
                (void) safe_close(*fd);
        }
}

int loop_device_make(
                int fd,
                int open_flags,
                uint64_t offset,
                uint64_t size,
                uint32_t loop_flags,
                LoopDevice **ret) {

        _cleanup_free_ char *loopdev = NULL;
        struct loop_info64 info;
        LoopDevice *d = NULL;
        struct stat st;
        int nr = -1, r;

        assert(fd >= 0);
        assert(ret);
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISBLK(st.st_mode)) {
                if (ioctl(fd, LOOP_GET_STATUS64, &info) >= 0) {
                        /* Oh! This is a loopback device? That's interesting! */

#if HAVE_VALGRIND_MEMCHECK_H
                        /* Valgrind currently doesn't know LOOP_GET_STATUS64. Remove this once it does */
                        VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif
                        nr = info.lo_number;

                        if (asprintf(&loopdev, "/dev/loop%i", nr) < 0)
                                return -ENOMEM;
                }

                if (offset == 0 && IN_SET(size, 0, UINT64_MAX)) {
                        _cleanup_close_ int copy = -1;

                        /* If this is already a block device, store a copy of the fd as it is */

                        copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                        if (copy < 0)
                                return -errno;

                        d = new(LoopDevice, 1);
                        if (!d)
                                return -ENOMEM;
                        *d = (LoopDevice) {
                                .fd = TAKE_FD(copy),
                                .nr = nr,
                                .node = TAKE_PTR(loopdev),
                                .relinquished = true, /* It's not allocated by us, don't destroy it when this object is freed */
                        };

                        *ret = d;
                        return d->fd;
                }
        } else {
                r = stat_verify_regular(&st);
                if (r < 0)
                        return r;
        }

        _cleanup_close_ int control = -1;
        _cleanup_(cleanup_clear_loop_close) int loop_with_fd = -1;

        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0)
                return -errno;

        /* Loop around LOOP_CTL_GET_FREE, since at the moment we attempt to open the returned device it might
         * be gone already, taken by somebody else racing against us. */
        for (unsigned n_attempts = 0;;) {
                _cleanup_close_ int loop = -1;

                nr = ioctl(control, LOOP_CTL_GET_FREE);
                if (nr < 0)
                        return -errno;

                if (asprintf(&loopdev, "/dev/loop%i", nr) < 0)
                        return -ENOMEM;

                loop = open(loopdev, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|open_flags);
                if (loop < 0) {
                        /* Somebody might've gotten the same number from the kernel, used the device,
                         * and called LOOP_CTL_REMOVE on it. Let's retry with a new number. */
                        if (errno != ENOENT)
                                return -errno;
                } else {
                        if (ioctl(loop, LOOP_SET_FD, fd) >= 0) {
                                loop_with_fd = TAKE_FD(loop);
                                break;
                        }
                        if (errno != EBUSY)
                                return -errno;
                }

                if (++n_attempts >= 64) /* Give up eventually */
                        return -EBUSY;

                loopdev = mfree(loopdev);
        }

        info = (struct loop_info64) {
                /* Use the specified flags, but configure the read-only flag from the open flags, and force autoclear */
                .lo_flags = (loop_flags & ~LO_FLAGS_READ_ONLY) | ((loop_flags & O_ACCMODE) == O_RDONLY ? LO_FLAGS_READ_ONLY : 0) | LO_FLAGS_AUTOCLEAR,
                .lo_offset = offset,
                .lo_sizelimit = size == UINT64_MAX ? 0 : size,
        };

        if (ioctl(loop_with_fd, LOOP_SET_STATUS64, &info) < 0)
                return -errno;

        d = new(LoopDevice, 1);
        if (!d)
                return -ENOMEM;
        *d = (LoopDevice) {
                .fd = TAKE_FD(loop_with_fd),
                .node = TAKE_PTR(loopdev),
                .nr = nr,
        };

        *ret = d;
        return 0;
}

int loop_device_make_by_path(const char *path, int open_flags, uint32_t loop_flags, LoopDevice **ret) {
        _cleanup_close_ int fd = -1;
        int r;

        assert(path);
        assert(ret);
        assert(open_flags < 0 || IN_SET(open_flags, O_RDWR, O_RDONLY));

        /* Passing < 0 as open_flags here means we'll try to open the device writable if we can, retrying
         * read-only if we cannot. */

        fd = open(path, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|(open_flags >= 0 ? open_flags : O_RDWR));
        if (fd < 0) {
                r = -errno;

                /* Retry read-only? */
                if (open_flags >= 0 || !(ERRNO_IS_PRIVILEGE(r) || r == -EROFS))
                        return r;

                fd = open(path, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_RDONLY);
                if (fd < 0)
                        return r; /* Propagate original error */

                open_flags = O_RDONLY;
        } else if (open_flags < 0)
                open_flags = O_RDWR;

        return loop_device_make(fd, open_flags, 0, 0, loop_flags, ret);
}

LoopDevice* loop_device_unref(LoopDevice *d) {
        if (!d)
                return NULL;

        if (d->fd >= 0) {
                /* Implicitly sync the device, since otherwise in-flight blocks might not get written */
                if (fsync(d->fd) < 0)
                        log_debug_errno(errno, "Failed to sync loop block device, ignoring: %m");

                if (d->nr >= 0 && !d->relinquished) {
                        if (ioctl(d->fd, LOOP_CLR_FD) < 0)
                                log_debug_errno(errno, "Failed to clear loop device: %m");

                }

                safe_close(d->fd);
        }

        if (d->nr >= 0 && !d->relinquished) {
                _cleanup_close_ int control = -1;

                control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (control < 0)
                        log_warning_errno(errno,
                                          "Failed to open loop control device, cannot remove loop device %s: %m",
                                          strna(d->node));
                else
                        for (unsigned n_attempts = 0;;) {
                                if (ioctl(control, LOOP_CTL_REMOVE, d->nr) >= 0)
                                        break;
                                if (errno != EBUSY || ++n_attempts >= 64) {
                                        log_warning_errno(errno, "Failed to remove device %s: %m", strna(d->node));
                                        break;
                                }
                                (void) usleep(50 * USEC_PER_MSEC);
                        }
        }

        free(d->node);
        return mfree(d);
}

void loop_device_relinquish(LoopDevice *d) {
        assert(d);

        /* Don't attempt to clean up the loop device anymore from this point on. Leave the clean-ing up to the kernel
         * itself, using the loop device "auto-clear" logic we already turned on when creating the device. */

        d->relinquished = true;
}

int loop_device_open(const char *loop_path, int open_flags, LoopDevice **ret) {
        _cleanup_close_ int loop_fd = -1;
        _cleanup_free_ char *p = NULL;
        struct loop_info64 info;
        struct stat st;
        LoopDevice *d;
        int nr;

        assert(loop_path);
        assert(ret);

        loop_fd = open(loop_path, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|open_flags);
        if (loop_fd < 0)
                return -errno;

        if (fstat(loop_fd, &st) < 0)
                return -errno;
        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        if (ioctl(loop_fd, LOOP_GET_STATUS64, &info) >= 0) {
#if HAVE_VALGRIND_MEMCHECK_H
                /* Valgrind currently doesn't know LOOP_GET_STATUS64. Remove this once it does */
                VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif
                nr = info.lo_number;
        } else
                nr = -1;

        p = strdup(loop_path);
        if (!p)
                return -ENOMEM;

        d = new(LoopDevice, 1);
        if (!d)
                return -ENOMEM;

        *d = (LoopDevice) {
                .fd = TAKE_FD(loop_fd),
                .nr = nr,
                .node = TAKE_PTR(p),
                .relinquished = true, /* It's not ours, don't try to destroy it when this object is freed */
        };

        *ret = d;
        return d->fd;
}

static int resize_partition(int partition_fd, uint64_t offset, uint64_t size) {
        char sysfs[STRLEN("/sys/dev/block/:/partition") + 2*DECIMAL_STR_MAX(dev_t) + 1];
        _cleanup_free_ char *whole = NULL, *buffer = NULL;
        uint64_t current_offset, current_size, partno;
        _cleanup_close_ int whole_fd = -1;
        struct stat st;
        dev_t devno;
        int r;

        assert(partition_fd >= 0);

        /* Resizes the partition the loopback device refer to (assuming it refers to one instead of an actual
         * loopback device), and changes the offset, if needed. This is a fancy wrapper around
         * BLKPG_RESIZE_PARTITION. */

        if (fstat(partition_fd, &st) < 0)
                return -errno;

        assert(S_ISBLK(st.st_mode));

        xsprintf(sysfs, "/sys/dev/block/%u:%u/partition", major(st.st_rdev), minor(st.st_rdev));
        r = read_one_line_file(sysfs, &buffer);
        if (r == -ENOENT) /* not a partition, cannot resize */
                return -ENOTTY;
        if (r < 0)
                return r;
        r = safe_atou64(buffer, &partno);
        if (r < 0)
                return r;

        xsprintf(sysfs, "/sys/dev/block/%u:%u/start", major(st.st_rdev), minor(st.st_rdev));

        buffer = mfree(buffer);
        r = read_one_line_file(sysfs, &buffer);
        if (r < 0)
                return r;
        r = safe_atou64(buffer, &current_offset);
        if (r < 0)
                return r;
        if (current_offset > UINT64_MAX/512U)
                return -EINVAL;
        current_offset *= 512U;

        if (ioctl(partition_fd, BLKGETSIZE64, &current_size) < 0)
                return -EINVAL;

        if (size == UINT64_MAX && offset == UINT64_MAX)
                return 0;
        if (current_size == size && current_offset == offset)
                return 0;

        xsprintf(sysfs, "/sys/dev/block/%u:%u/../dev", major(st.st_rdev), minor(st.st_rdev));

        buffer = mfree(buffer);
        r = read_one_line_file(sysfs, &buffer);
        if (r < 0)
                return r;
        r = parse_dev(buffer, &devno);
        if (r < 0)
                return r;

        r = device_path_make_major_minor(S_IFBLK, devno, &whole);
        if (r < 0)
                return r;

        whole_fd = open(whole, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (whole_fd < 0)
                return -errno;

        struct blkpg_partition bp = {
                .pno = partno,
                .start = offset == UINT64_MAX ? current_offset : offset,
                .length = size == UINT64_MAX ? current_size : size,
        };

        struct blkpg_ioctl_arg ba = {
                .op = BLKPG_RESIZE_PARTITION,
                .data = &bp,
                .datalen = sizeof(bp),
        };

        if (ioctl(whole_fd, BLKPG, &ba) < 0)
                return -errno;

        return 0;
}

int loop_device_refresh_size(LoopDevice *d, uint64_t offset, uint64_t size) {
        struct loop_info64 info;
        assert(d);

        /* Changes the offset/start of the loop device relative to the beginning of the underlying file or
         * block device. If this loop device actually refers to a partition and not a loopback device, we'll
         * try to adjust the partition offsets instead.
         *
         * If either offset or size is UINT64_MAX we won't change that parameter. */

        if (d->fd < 0)
                return -EBADF;

        if (d->nr < 0) /* not a loopback device */
                return resize_partition(d->fd, offset, size);

        if (ioctl(d->fd, LOOP_GET_STATUS64, &info) < 0)
                return -errno;

#if HAVE_VALGRIND_MEMCHECK_H
        /* Valgrind currently doesn't know LOOP_GET_STATUS64. Remove this once it does */
        VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

        if (size == UINT64_MAX && offset == UINT64_MAX)
                return 0;
        if (info.lo_sizelimit == size && info.lo_offset == offset)
                return 0;

        if (size != UINT64_MAX)
                info.lo_sizelimit = size;
        if (offset != UINT64_MAX)
                info.lo_offset = offset;

        if (ioctl(d->fd, LOOP_SET_STATUS64, &info) < 0)
                return -errno;

        return 0;
}

int loop_device_flock(LoopDevice *d, int operation) {
        assert(d);

        if (d->fd < 0)
                return -EBADF;

        if (flock(d->fd, operation) < 0)
                return -errno;

        return 0;
}
