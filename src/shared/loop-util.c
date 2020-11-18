/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

#include "sd-device.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "loop-util.h"
#include "missing_loop.h"
#include "parse-util.h"
#include "random-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tmpfile-util.h"

static void cleanup_clear_loop_close(int *fd) {
        if (*fd < 0)
                return;

        (void) ioctl(*fd, LOOP_CLR_FD);
        (void) safe_close(*fd);
}

static int loop_is_bound(int fd) {
        struct loop_info64 info;

        assert(fd >= 0);

        if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {
                if (errno == ENXIO)
                        return false; /* not bound! */

                return -errno;
        }

        return true; /* bound! */
}

static int device_has_block_children(sd_device *d) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        const char *main_sn, *main_ss;
        sd_device *q;
        int r;

        assert(d);

        /* Checks if the specified device currently has block device children (i.e. partition block
         * devices). */

        r = sd_device_get_sysname(d, &main_sn);
        if (r < 0)
                return r;

        r = sd_device_get_subsystem(d, &main_ss);
        if (r < 0)
                return r;

        if (!streq(main_ss, "block"))
                return -EINVAL;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_parent(e, d);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, q) {
                const char *ss, *sn;

                r = sd_device_get_subsystem(q, &ss);
                if (r < 0)
                        continue;

                if (!streq(ss, "block"))
                        continue;

                r = sd_device_get_sysname(q, &sn);
                if (r < 0)
                        continue;

                if (streq(sn, main_sn))
                        continue;

                return 1; /* we have block device children */
        }

        return 0;
}

static int loop_configure(
                int fd,
                int nr,
                const struct loop_config *c,
                bool *try_loop_configure) {

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *sysname = NULL;
        _cleanup_close_ int lock_fd = -1;
        int r;

        assert(fd >= 0);
        assert(nr >= 0);
        assert(c);
        assert(try_loop_configure);

        if (asprintf(&sysname, "loop%i", nr) < 0)
                return -ENOMEM;

        r = sd_device_new_from_subsystem_sysname(&d, "block", sysname);
        if (r < 0)
                return r;

        /* Let's lock the device before we do anything. We take the BSD lock on a second, separately opened
         * fd for the device. udev after all watches for close() events (specifically IN_CLOSE_WRITE) on
         * block devices to reprobe them, hence by having a separate fd we will later close() we can ensure
         * we trigger udev after everything is done. If we'd lock our own fd instead and keep it open for a
         * long time udev would possibly never run on it again, even though the fd is unlocked, simply
         * because we never close() it. It also has the nice benefit we can use the _cleanup_close_ logic to
         * automatically release the lock, after we are done. */
        lock_fd = fd_reopen(fd, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (lock_fd < 0)
                return lock_fd;
        if (flock(lock_fd, LOCK_EX) < 0)
                return -errno;

        /* Let's see if the device is really detached, i.e. currently has no associated partition block
         * devices. On various kernels (such as 5.8) it is possible to have a loopback block device that
         * superficially is detached but still has partition block devices associated for it. They only go
         * away when the device is reattached. (Yes, LOOP_CLR_FD doesn't work then, because officially
         * nothing is attached and LOOP_CTL_REMOVE doesn't either, since it doesn't care about partition
         * block devices. */
        r = device_has_block_children(d);
        if (r < 0)
                return r;
        if (r > 0) {
                r = loop_is_bound(fd);
                if (r < 0)
                        return r;
                if (r > 0)
                        return -EBUSY;

                return -EUCLEAN; /* Bound but children? Tell caller to reattach something so that the
                                  * partition block devices are gone too. */
        }

        if (*try_loop_configure) {
                if (ioctl(fd, LOOP_CONFIGURE, c) < 0) {
                        /* Do fallback only if LOOP_CONFIGURE is not supported, propagate all other
                         * errors. Note that the kernel is weird: non-existing ioctls currently return EINVAL
                         * rather than ENOTTY on loopback block devices. They should fix that in the kernel,
                         * but in the meantime we accept both here. */
                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EINVAL)
                                return -errno;

                        *try_loop_configure = false;
                } else {
                        bool good = true;

                        if (c->info.lo_sizelimit != 0) {
                                /* Kernel 5.8 vanilla doesn't properly propagate the size limit into the
                                 * block device. If it's used, let's immediately check if it had the desired
                                 * effect hence. And if not use classic LOOP_SET_STATUS64. */
                                uint64_t z;

                                if (ioctl(fd, BLKGETSIZE64, &z) < 0) {
                                        r = -errno;
                                        goto fail;
                                }

                                if (z != c->info.lo_sizelimit) {
                                        log_debug("LOOP_CONFIGURE is broken, doesn't honour .lo_sizelimit. Falling back to LOOP_SET_STATUS64.");
                                        good = false;
                                }
                        }

                        if (FLAGS_SET(c->info.lo_flags, LO_FLAGS_PARTSCAN)) {
                                /* Kernel 5.8 vanilla doesn't properly propagate the partition scanning flag
                                 * into the block device. Let's hence verify if things work correctly here
                                 * before returning. */

                                r = blockdev_partscan_enabled(fd);
                                if (r < 0)
                                        goto fail;
                                if (r == 0) {
                                        log_debug("LOOP_CONFIGURE is broken, doesn't honour LO_FLAGS_PARTSCAN. Falling back to LOOP_SET_STATUS64.");
                                        good = false;
                                }
                        }

                        if (!good) {
                                /* LOOP_CONFIGURE doesn't work. Remember that. */
                                *try_loop_configure = false;

                                /* We return EBUSY here instead of retrying immediately with LOOP_SET_FD,
                                 * because LOOP_CLR_FD is async: if the operation cannot be executed right
                                 * away it just sets the autoclear flag on the device. This means there's a
                                 * good chance we cannot actually reuse the loopback device right-away. Hence
                                 * let's assume it's busy, avoid the trouble and let the calling loop call us
                                 * again with a new, likely unused device. */
                                r = -EBUSY;
                                goto fail;
                        }

                        return 0;
                }
        }

        /* Since kernel commit 5db470e229e22b7eda6e23b5566e532c96fb5bc3 (kernel v5.0) the LOOP_SET_STATUS64
         * ioctl can return EAGAIN in case we change the lo_offset field, if someone else is accessing the
         * block device while we try to reconfigure it. This is a pretty common case, since udev might
         * instantly start probing the device as soon as we attach an fd to it. Hence handle it in two ways:
         * first, let's take the BSD lock to ensure that udev will not step in between the point in
         * time where we attach the fd and where we reconfigure the device. Secondly, let's wait 50ms on
         * EAGAIN and retry. The former should be an efficient mechanism to avoid we have to wait 50ms
         * needlessly if we are just racing against udev. The latter is protection against all other cases,
         * i.e. peers that do not take the BSD lock. */

        if (ioctl(fd, LOOP_SET_FD, c->fd) < 0)
                return -errno;

        for (unsigned n_attempts = 0;;) {
                if (ioctl(fd, LOOP_SET_STATUS64, &c->info) >= 0)
                        break;
                if (errno != EAGAIN || ++n_attempts >= 64) {
                        r = log_debug_errno(errno, "Failed to configure loopback device: %m");
                        goto fail;
                }

                /* Sleep some random time, but at least 10ms, at most 250ms. Increase the delay the more
                 * failed attempts we see */
                (void) usleep(UINT64_C(10) * USEC_PER_MSEC +
                              random_u64() % (UINT64_C(240) * USEC_PER_MSEC * n_attempts/64));
        }

        return 0;

fail:
        (void) ioctl(fd, LOOP_CLR_FD);
        return r;
}

static int attach_empty_file(int loop, int nr) {
        _cleanup_close_ int fd = -1;

        /* So here's the thing: on various kernels (5.8 at least) loop block devices might enter a state
         * where they are detached but nonetheless have partitions, when used heavily. Accessing these
         * partitions results in immediatey IO errors. There's no pretty way to get rid of them
         * again. Neither LOOP_CLR_FD nor LOOP_CTL_REMOVE suffice (see above). What does work is to
         * reassociate them with a new fd however. This is what we do here hence: we associate the devices
         * with an empty file (i.e. an image that definitely has no partitions). We then immediately clear it
         * again. This suffices to make the partitions go away. Ugly but appears to work. */

        log_debug("Found unattached loopback block device /dev/loop%i with partitions. Attaching empty file to remove them.", nr);

        fd = open_tmpfile_unlinkable(NULL, O_RDONLY);
        if (fd < 0)
                return fd;

        if (flock(loop, LOCK_EX) < 0)
                return -errno;

        if (ioctl(loop, LOOP_SET_FD, fd) < 0)
                return -errno;

        if (ioctl(loop, LOOP_SET_STATUS64, &(struct loop_info64) {
                                .lo_flags = LO_FLAGS_READ_ONLY|
                                            LO_FLAGS_AUTOCLEAR|
                                            LO_FLAGS_PARTSCAN, /* enable partscan, so that the partitions really go away */
                        }) < 0)
                return -errno;

        if (ioctl(loop, LOOP_CLR_FD) < 0)
                return -errno;

        /* The caller is expected to immediately close the loopback device after this, so that the BSD lock
         * is released, and udev sees the changes. */
        return 0;
}

int loop_device_make(
                int fd,
                int open_flags,
                uint64_t offset,
                uint64_t size,
                uint32_t loop_flags,
                LoopDevice **ret) {

        _cleanup_free_ char *loopdev = NULL;
        bool try_loop_configure = true;
        struct loop_config config;
        LoopDevice *d = NULL;
        struct stat st;
        int nr = -1, r;

        assert(fd >= 0);
        assert(ret);
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISBLK(st.st_mode)) {
                if (ioctl(fd, LOOP_GET_STATUS64, &config.info) >= 0) {
                        /* Oh! This is a loopback device? That's interesting! */

#if HAVE_VALGRIND_MEMCHECK_H
                        /* Valgrind currently doesn't know LOOP_GET_STATUS64. Remove this once it does */
                        VALGRIND_MAKE_MEM_DEFINED(&config.info, sizeof(config.info));
#endif
                        nr = config.info.lo_number;

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

        config = (struct loop_config) {
                .fd = fd,
                .info = {
                        /* Use the specified flags, but configure the read-only flag from the open flags, and force autoclear */
                        .lo_flags = (loop_flags & ~LO_FLAGS_READ_ONLY) | ((open_flags & O_ACCMODE) == O_RDONLY ? LO_FLAGS_READ_ONLY : 0) | LO_FLAGS_AUTOCLEAR,
                        .lo_offset = offset,
                        .lo_sizelimit = size == UINT64_MAX ? 0 : size,
                },
        };

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
                        if (!IN_SET(errno, ENOENT, ENXIO))
                                return -errno;
                } else {
                        r = loop_configure(loop, nr, &config, &try_loop_configure);
                        if (r >= 0) {
                                loop_with_fd = TAKE_FD(loop);
                                break;
                        }
                        if (r == -EUCLEAN) {
                                /* Make left-over partition disappear hack (see above) */
                                r = attach_empty_file(loop, nr);
                                if (r < 0 && r != -EBUSY)
                                        return r;
                        } else if (r != -EBUSY)
                                return r;
                }

                if (++n_attempts >= 64) /* Give up eventually */
                        return -EBUSY;

                loopdev = mfree(loopdev);

                /* Wait some random time, to make collision less likely. Let's pick a random time in the
                 * range 0ms…250ms, linearly scaled by the number of failed attempts. */
                (void) usleep(random_u64() % (UINT64_C(10) * USEC_PER_MSEC +
                                              UINT64_C(240) * USEC_PER_MSEC * n_attempts/64));
        }

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

int loop_device_sync(LoopDevice *d) {
        assert(d);

        /* We also do this implicitly in loop_device_unref(). Doing this explicitly here has the benefit that
         * we can check the return value though. */

        if (d->fd < 0)
                return -EBADF;

        if (fsync(d->fd) < 0)
                return -errno;

        return 0;
}
