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
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "loop-util.h"
#include "missing_fs.h"
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

static int get_current_uevent_seqnum(uint64_t *ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = read_full_virtual_file("/sys/kernel/uevent_seqnum", &p, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to read current uevent sequence number: %m");

        truncate_nl(p);

        r = safe_atou64(p, ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse current uevent sequence number: %s", p);

        return 0;
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

static int loop_get_diskseq(int fd, uint64_t *ret_diskseq) {
        uint64_t diskseq;

        assert(fd >= 0);
        assert(ret_diskseq);

        if (ioctl(fd, BLKGETDISKSEQ, &diskseq) < 0) {
                /* Note that the kernel is weird: non-existing ioctls currently return EINVAL
                 * rather than ENOTTY on loopback block devices. They should fix that in the kernel,
                 * but in the meantime we accept both here. */
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EINVAL)
                        return -errno;

                return -EOPNOTSUPP;
        }

        *ret_diskseq = diskseq;

        return 0;
}

static int loop_configure(
                int fd,
                int nr,
                const struct loop_config *c,
                bool *try_loop_configure,
                uint64_t *ret_seqnum_not_before,
                usec_t *ret_timestamp_not_before) {

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *sysname = NULL;
        _cleanup_close_ int lock_fd = -1;
        struct loop_info64 info_copy;
        uint64_t seqnum;
        usec_t timestamp;
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
                /* Acquire uevent seqnum immediately before attaching the loopback device. This allows
                 * callers to ignore all uevents with a seqnum before this one, if they need to associate
                 * uevent with this attachment. Doing so isn't race-free though, as uevents that happen in
                 * the window between this reading of the seqnum, and the LOOP_CONFIGURE call might still be
                 * mistaken as originating from our attachment, even though might be caused by an earlier
                 * use. But doing this at least shortens the race window a bit. */
                r = get_current_uevent_seqnum(&seqnum);
                if (r < 0)
                        return r;
                timestamp = now(CLOCK_MONOTONIC);

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

                        if (ret_seqnum_not_before)
                                *ret_seqnum_not_before = seqnum;
                        if (ret_timestamp_not_before)
                                *ret_timestamp_not_before = timestamp;

                        return 0;
                }
        }

        /* Let's read the seqnum again, to shorten the window. */
        r = get_current_uevent_seqnum(&seqnum);
        if (r < 0)
                return r;
        timestamp = now(CLOCK_MONOTONIC);

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

        /* Only some of the flags LOOP_CONFIGURE can set are also settable via LOOP_SET_STATUS64, hence mask
         * them out. */
        info_copy = c->info;
        info_copy.lo_flags &= LOOP_SET_STATUS_SETTABLE_FLAGS;

        for (unsigned n_attempts = 0;;) {
                if (ioctl(fd, LOOP_SET_STATUS64, &info_copy) >= 0)
                        break;
                if (errno != EAGAIN || ++n_attempts >= 64) {
                        r = log_debug_errno(errno, "Failed to configure loopback device: %m");
                        goto fail;
                }

                /* Sleep some random time, but at least 10ms, at most 250ms. Increase the delay the more
                 * failed attempts we see */
                (void) usleep(UINT64_C(10) * USEC_PER_MSEC +
                              random_u64_range(UINT64_C(240) * USEC_PER_MSEC * n_attempts/64));
        }

        /* Work around a kernel bug, where changing offset/size of the loopback device doesn't correctly
         * invalidate the buffer cache. For details see:
         *
         *     https://android.googlesource.com/platform/system/apex/+/bef74542fbbb4cd629793f4efee8e0053b360570
         *
         * This was fixed in kernel 5.0, see:
         *
         *     https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5db470e229e22b7eda6e23b5566e532c96fb5bc3
         *
         * We'll run the work-around here in the legacy LOOP_SET_STATUS64 codepath. In the LOOP_CONFIGURE
         * codepath above it should not be necessary. */
        if (c->info.lo_offset != 0 || c->info.lo_sizelimit != 0)
                if (ioctl(fd, BLKFLSBUF, 0) < 0)
                        log_debug_errno(errno, "Failed to issue BLKFLSBUF ioctl, ignoring: %m");

        /* LO_FLAGS_DIRECT_IO is a flags we need to configure via explicit ioctls. */
        if (FLAGS_SET(c->info.lo_flags, LO_FLAGS_DIRECT_IO)) {
                unsigned long b = 1;

                if (ioctl(fd, LOOP_SET_DIRECT_IO, b) < 0)
                        log_debug_errno(errno, "Failed to enable direct IO mode on loopback device /dev/loop%i, ignoring: %m", nr);
        }

        if (ret_seqnum_not_before)
                *ret_seqnum_not_before = seqnum;
        if (ret_timestamp_not_before)
                *ret_timestamp_not_before = timestamp;

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

static int loop_device_make_internal(
                int fd,
                int open_flags,
                uint64_t offset,
                uint64_t size,
                uint32_t loop_flags,
                LoopDevice **ret) {

        _cleanup_close_ int direct_io_fd = -1;
        _cleanup_free_ char *loopdev = NULL;
        bool try_loop_configure = true;
        struct loop_config config;
        LoopDevice *d = NULL;
        uint64_t seqnum = UINT64_MAX;
        usec_t timestamp = USEC_INFINITY;
        int nr = -1, r, f_flags;
        struct stat st;

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
                        uint64_t diskseq = 0;

                        /* If this is already a block device and we are supposed to cover the whole of it
                         * then store an fd to the original open device node — and do not actually create an
                         * unnecessary loopback device for it. Note that we reopen the inode here, instead of
                         * keeping just a dup() clone of it around, since we want to ensure that the O_DIRECT
                         * flag of the handle we keep is off, we have our own file index, and have the right
                         * read/write mode in effect. */

                        copy = fd_reopen(fd, open_flags|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                        if (copy < 0)
                                return copy;

                        r = loop_get_diskseq(copy, &diskseq);
                        if (r < 0 && r != -EOPNOTSUPP)
                                return r;

                        d = new(LoopDevice, 1);
                        if (!d)
                                return -ENOMEM;
                        *d = (LoopDevice) {
                                .fd = TAKE_FD(copy),
                                .nr = nr,
                                .node = TAKE_PTR(loopdev),
                                .relinquished = true, /* It's not allocated by us, don't destroy it when this object is freed */
                                .devno = st.st_rdev,
                                .diskseq = diskseq,
                                .uevent_seqnum_not_before = UINT64_MAX,
                                .timestamp_not_before = USEC_INFINITY,
                        };

                        *ret = d;
                        return d->fd;
                }
        } else {
                r = stat_verify_regular(&st);
                if (r < 0)
                        return r;
        }

        f_flags = fcntl(fd, F_GETFL);
        if (f_flags < 0)
                return -errno;

        if (FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO) != FLAGS_SET(f_flags, O_DIRECT)) {
                /* If LO_FLAGS_DIRECT_IO is requested, then make sure we have the fd open with O_DIRECT, as
                 * that's required. Conversely, if it's off require that O_DIRECT is off too (that's because
                 * new kernels will implicitly enable LO_FLAGS_DIRECT_IO if O_DIRECT is set).
                 *
                 * Our intention here is that LO_FLAGS_DIRECT_IO is the primary knob, and O_DIRECT derived
                 * from that automatically. */

                direct_io_fd = fd_reopen(fd, (FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO) ? O_DIRECT : 0)|O_CLOEXEC|O_NONBLOCK|open_flags);
                if (direct_io_fd < 0) {
                        if (!FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO))
                                return log_debug_errno(errno, "Failed to reopen file descriptor without O_DIRECT: %m");

                        /* Some file systems might not support O_DIRECT, let's gracefully continue without it then. */
                        log_debug_errno(errno, "Failed to enable O_DIRECT for backing file descriptor for loopback device. Continuing without.");
                        loop_flags &= ~LO_FLAGS_DIRECT_IO;
                } else
                        fd = direct_io_fd; /* From now on, operate on our new O_DIRECT fd */
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
                        r = loop_configure(loop, nr, &config, &try_loop_configure, &seqnum, &timestamp);
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
                (void) usleep(random_u64_range(UINT64_C(10) * USEC_PER_MSEC +
                                               UINT64_C(240) * USEC_PER_MSEC * n_attempts/64));
        }

        if (FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO)) {
                struct loop_info64 info;

                if (ioctl(loop_with_fd, LOOP_GET_STATUS64, &info) < 0)
                        return -errno;

#if HAVE_VALGRIND_MEMCHECK_H
                VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

                /* On older kernels (<= 5.3) it was necessary to set the block size of the loopback block
                 * device to the logical block size of the underlying file system. Since there was no nice
                 * way to query the value, we are not bothering to do this however. On newer kernels the
                 * block size is propagated automatically and does not require intervention from us. We'll
                 * check here if enabling direct IO worked, to make this easily debuggable however.
                 *
                 * (Should anyone really care and actually wants direct IO on old kernels: it might be worth
                 * enabling direct IO with iteratively larger block sizes until it eventually works.) */
                if (!FLAGS_SET(info.lo_flags, LO_FLAGS_DIRECT_IO))
                        log_debug("Could not enable direct IO mode, proceeding in buffered IO mode.");
        }

        if (fstat(loop_with_fd, &st) < 0)
                return -errno;
        assert(S_ISBLK(st.st_mode));

        uint64_t diskseq = 0;
        r = loop_get_diskseq(loop_with_fd, &diskseq);
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        d = new(LoopDevice, 1);
        if (!d)
                return -ENOMEM;
        *d = (LoopDevice) {
                .fd = TAKE_FD(loop_with_fd),
                .node = TAKE_PTR(loopdev),
                .nr = nr,
                .devno = st.st_rdev,
                .diskseq = diskseq,
                .uevent_seqnum_not_before = seqnum,
                .timestamp_not_before = timestamp,
        };

        *ret = d;
        return d->fd;
}

static uint32_t loop_flags_mangle(uint32_t loop_flags) {
        int r;

        r = getenv_bool("SYSTEMD_LOOP_DIRECT_IO");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_LOOP_DIRECT_IO, ignoring: %m");

        return UPDATE_FLAG(loop_flags, LO_FLAGS_DIRECT_IO, r != 0); /* Turn on LO_FLAGS_DIRECT_IO by default, unless explicitly configured to off. */
}

int loop_device_make(
                int fd,
                int open_flags,
                uint64_t offset,
                uint64_t size,
                uint32_t loop_flags,
                LoopDevice **ret) {

        assert(fd >= 0);
        assert(ret);

        return loop_device_make_internal(
                        fd,
                        open_flags,
                        offset,
                        size,
                        loop_flags_mangle(loop_flags),
                        ret);
}

int loop_device_make_by_path(
                const char *path,
                int open_flags,
                uint32_t loop_flags,
                LoopDevice **ret) {

        int r, basic_flags, direct_flags, rdwr_flags;
        _cleanup_close_ int fd = -1;
        bool direct = false;

        assert(path);
        assert(ret);
        assert(open_flags < 0 || IN_SET(open_flags, O_RDWR, O_RDONLY));

        /* Passing < 0 as open_flags here means we'll try to open the device writable if we can, retrying
         * read-only if we cannot. */

        loop_flags = loop_flags_mangle(loop_flags);

        /* Let's open with O_DIRECT if we can. But not all file systems support that, hence fall back to
         * non-O_DIRECT mode automatically, if it fails. */

        basic_flags = O_CLOEXEC|O_NONBLOCK|O_NOCTTY;
        direct_flags = FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO) ? O_DIRECT : 0;
        rdwr_flags = open_flags >= 0 ? open_flags : O_RDWR;

        fd = open(path, basic_flags|direct_flags|rdwr_flags);
        if (fd < 0 && direct_flags != 0) /* If we had O_DIRECT on, and things failed with that, let's immediately try again without */
                fd = open(path, basic_flags|rdwr_flags);
        else
                direct = direct_flags != 0;
        if (fd < 0) {
                r = -errno;

                /* Retry read-only? */
                if (open_flags >= 0 || !(ERRNO_IS_PRIVILEGE(r) || r == -EROFS))
                        return r;

                fd = open(path, basic_flags|direct_flags|O_RDONLY);
                if (fd < 0 && direct_flags != 0) /* as above */
                        fd = open(path, basic_flags|O_RDONLY);
                else
                        direct = direct_flags != 0;
                if (fd < 0)
                        return r; /* Propagate original error */

                open_flags = O_RDONLY;
        } else if (open_flags < 0)
                open_flags = O_RDWR;

        log_debug("Opened '%s' in %s access mode%s, with O_DIRECT %s%s.",
                  path,
                  open_flags == O_RDWR ? "O_RDWR" : "O_RDONLY",
                  open_flags != rdwr_flags ? " (O_RDWR was requested but not allowed)" : "",
                  direct ? "enabled" : "disabled",
                  direct != (direct_flags != 0) ? " (O_DIRECT was requested but not supported)" : "");

        return loop_device_make_internal(fd, open_flags, 0, 0, loop_flags, ret);
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
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));
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
                .devno = st.st_dev,
                .uevent_seqnum_not_before = UINT64_MAX,
                .timestamp_not_before = USEC_INFINITY,
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

        return RET_NERRNO(ioctl(whole_fd, BLKPG, &ba));
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

        return RET_NERRNO(ioctl(d->fd, LOOP_SET_STATUS64, &info));
}

int loop_device_flock(LoopDevice *d, int operation) {
        assert(d);

        if (d->fd < 0)
                return -EBADF;

        return RET_NERRNO(flock(d->fd, operation));
}

int loop_device_sync(LoopDevice *d) {
        assert(d);

        /* We also do this implicitly in loop_device_unref(). Doing this explicitly here has the benefit that
         * we can check the return value though. */

        if (d->fd < 0)
                return -EBADF;

        return RET_NERRNO(fsync(d->fd));
}
