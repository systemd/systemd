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
#include "data-fd-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fileio.h"
#include "loop-util.h"
#include "missing_loop.h"
#include "parse-util.h"
#include "path-util.h"
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

        if (ioctl(ASSERT_FD(fd), LOOP_GET_STATUS64, &info) < 0) {
                if (errno == ENXIO)
                        return false; /* not bound! */

                return -errno;
        }

        return true; /* bound! */
}

static int get_current_uevent_seqnum(uint64_t *ret) {
        _cleanup_free_ void *p = NULL;
        int r;

        r = read_full_virtual_file("/sys/kernel/uevent_seqnum", &p, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to read current uevent sequence number: %m");

        r = safe_atou64(strstrip(p), ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse current uevent sequence number: %s", p);

        return 0;
}

static int open_lock_fd(int primary_fd, int operation) {
        _cleanup_close_ int lock_fd = -EBADF;

        assert(IN_SET(operation & ~LOCK_NB, LOCK_SH, LOCK_EX));

        lock_fd = fd_reopen(ASSERT_FD(primary_fd), O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (lock_fd < 0)
                return lock_fd;

        if (flock(lock_fd, operation) < 0)
                return -errno;

        return TAKE_FD(lock_fd);
}

static int loop_configure_verify_direct_io(int fd, const struct loop_config *c) {
        assert(fd >= 0);
        assert(c);

        if (FLAGS_SET(c->info.lo_flags, LO_FLAGS_DIRECT_IO)) {
                struct loop_info64 info;

                if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0)
                        return log_debug_errno(errno, "Failed to issue LOOP_GET_STATUS64: %m");

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
                 * enabling direct IO with iteratively larger block sizes until it eventually works.)
                 *
                 * On older kernels (e.g.: 5.10) when this is attempted on a file stored on a dm-crypt
                 * backed partition the kernel will start returning I/O errors when accessing the mounted
                 * loop device, so return a recognizable error that causes the operation to be started
                 * from scratch without the LO_FLAGS_DIRECT_IO flag. */
                if (!FLAGS_SET(info.lo_flags, LO_FLAGS_DIRECT_IO))
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(ENOANO),
                                        "Could not enable direct IO mode, retrying in buffered IO mode.");
        }

        return 0;
}

static int loop_configure_verify(int fd, const struct loop_config *c) {
        bool broken = false;
        int r;

        assert(fd >= 0);
        assert(c);

        if (c->block_size != 0) {
                uint32_t ssz;

                r = blockdev_get_sector_size(fd, &ssz);
                if (r < 0)
                        return r;

                if (ssz != c->block_size) {
                        log_debug("LOOP_CONFIGURE didn't honour requested block size %" PRIu32 ", got %" PRIu32 " instead. Ignoring.", c->block_size, ssz);
                        broken = true;
                }
        }

        if (c->info.lo_sizelimit != 0) {
                /* Kernel 5.8 vanilla doesn't properly propagate the size limit into the
                 * block device. If it's used, let's immediately check if it had the desired
                 * effect hence. And if not use classic LOOP_SET_STATUS64. */
                uint64_t z;

                r = blockdev_get_device_size(fd, &z);
                if (r < 0)
                        return r;

                if (z != c->info.lo_sizelimit) {
                        log_debug("LOOP_CONFIGURE is broken, doesn't honour .info.lo_sizelimit. Falling back to LOOP_SET_STATUS64.");
                        broken = true;
                }
        }

        if (FLAGS_SET(c->info.lo_flags, LO_FLAGS_PARTSCAN)) {
                /* Kernel 5.8 vanilla doesn't properly propagate the partition scanning flag
                 * into the block device. Let's hence verify if things work correctly here
                 * before returning. */

                r = blockdev_partscan_enabled(fd);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("LOOP_CONFIGURE is broken, doesn't honour LO_FLAGS_PARTSCAN. Falling back to LOOP_SET_STATUS64.");
                        broken = true;
                }
        }

        r = loop_configure_verify_direct_io(fd, c);
        if (r < 0)
                return r;

        return !broken;
}

static int loop_configure_fallback(int fd, const struct loop_config *c) {
        struct loop_info64 info_copy;
        int r;

        assert(fd >= 0);
        assert(c);

        /* Only some of the flags LOOP_CONFIGURE can set are also settable via LOOP_SET_STATUS64, hence mask
         * them out. */
        info_copy = c->info;
        info_copy.lo_flags &= LOOP_SET_STATUS_SETTABLE_FLAGS;

        /* Since kernel commit 5db470e229e22b7eda6e23b5566e532c96fb5bc3 (kernel v5.0) the LOOP_SET_STATUS64
         * ioctl can return EAGAIN in case we change the info.lo_offset field, if someone else is accessing the
         * block device while we try to reconfigure it. This is a pretty common case, since udev might
         * instantly start probing the device as soon as we attach an fd to it. Hence handle it in two ways:
         * first, let's take the BSD lock to ensure that udev will not step in between the point in
         * time where we attach the fd and where we reconfigure the device. Secondly, let's wait 50ms on
         * EAGAIN and retry. The former should be an efficient mechanism to avoid we have to wait 50ms
         * needlessly if we are just racing against udev. The latter is protection against all other cases,
         * i.e. peers that do not take the BSD lock. */

        for (unsigned n_attempts = 0;;) {
                if (ioctl(fd, LOOP_SET_STATUS64, &info_copy) >= 0)
                        break;

                if (errno != EAGAIN || ++n_attempts >= 64)
                        return log_debug_errno(errno, "Failed to configure loopback block device: %m");

                /* Sleep some random time, but at least 10ms, at most 250ms. Increase the delay the more
                 * failed attempts we see */
                (void) usleep_safe(UINT64_C(10) * USEC_PER_MSEC +
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

        /* If a block size is requested then try to configure it. If that doesn't work, ignore errors, but
         * afterwards, let's validate what is in effect, and if it doesn't match what we want, fail */
        if (c->block_size != 0) {
                uint32_t ssz;

                if (ioctl(fd, LOOP_SET_BLOCK_SIZE, (unsigned long) c->block_size) < 0)
                        log_debug_errno(errno, "Failed to set sector size, ignoring: %m");

                r = blockdev_get_sector_size(fd, &ssz);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read sector size: %m");
                if (ssz != c->block_size)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Sector size of loopback device doesn't match what we requested, refusing.");
        }

        /* LO_FLAGS_DIRECT_IO is a flags we need to configure via explicit ioctls. */
        if (FLAGS_SET(c->info.lo_flags, LO_FLAGS_DIRECT_IO))
                if (ioctl(fd, LOOP_SET_DIRECT_IO, 1UL) < 0)
                        log_debug_errno(errno, "Failed to enable direct IO mode, ignoring: %m");

        return loop_configure_verify_direct_io(fd, c);
}

static int loop_configure(
                int nr,
                int open_flags,
                int lock_op,
                const struct loop_config *c,
                LoopDevice **ret) {

        static bool loop_configure_broken = false;

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_(cleanup_clear_loop_close) int loop_with_fd = -EBADF; /* This must be declared before lock_fd. */
        _cleanup_close_ int fd = -EBADF, lock_fd = -EBADF;
        _cleanup_free_ char *node = NULL;
        uint64_t diskseq = 0, seqnum = UINT64_MAX;
        usec_t timestamp = USEC_INFINITY;
        dev_t devno;
        int r;

        assert(nr >= 0);
        assert(c);
        assert(ret);

        if (asprintf(&node, "/dev/loop%i", nr) < 0)
                return log_oom_debug();

        r = sd_device_new_from_devname(&dev, node);
        if (r < 0)
                return log_debug_errno(r, "Failed to create sd_device object for \"%s\": %m", node);

        r = sd_device_get_devnum(dev, &devno);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devnum: %m");

        fd = sd_device_open(dev, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|open_flags);
        if (fd < 0)
                return log_device_debug_errno(dev, fd, "Failed to open device: %m");

        /* Let's lock the device before we do anything. We take the BSD lock on a second, separately opened
         * fd for the device. udev after all watches for close() events (specifically IN_CLOSE_WRITE) on
         * block devices to reprobe them, hence by having a separate fd we will later close() we can ensure
         * we trigger udev after everything is done. If we'd lock our own fd instead and keep it open for a
         * long time udev would possibly never run on it again, even though the fd is unlocked, simply
         * because we never close() it. It also has the nice benefit we can use the _cleanup_close_ logic to
         * automatically release the lock, after we are done. */
        lock_fd = open_lock_fd(fd, LOCK_EX);
        if (lock_fd < 0)
                return log_device_debug_errno(dev, lock_fd, "Failed to acquire lock: %m");

        log_device_debug(dev, "Acquired exclusive lock.");

        /* Let's see if backing file is really unattached. Someone may already attach a backing file without
         * taking BSD lock. */
        r = loop_is_bound(fd);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to check if the loopback block device is bound: %m");
        if (r > 0)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EBUSY),
                                              "The loopback block device is already bound, ignoring.");

        /* Let's see if the device is really detached, i.e. currently has no associated partition block
         * devices. On various kernels (such as 5.8) it is possible to have a loopback block device that
         * superficially is detached but still has partition block devices associated for it. Let's then
         * manually remove the partitions via BLKPG, and tell the caller we did that via EUCLEAN, so they try
         * again. */
        r = block_device_remove_all_partitions(dev, fd);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to remove partitions on the loopback block device: %m");
        if (r > 0)
                /* Removed all partitions. Let's report this to the caller, to try again, and count this as
                 * an attempt. */
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EUCLEAN),
                                              "Removed partitions on the loopback block device.");

        if (!loop_configure_broken) {
                /* Acquire uevent seqnum immediately before attaching the loopback device. This allows
                 * callers to ignore all uevents with a seqnum before this one, if they need to associate
                 * uevent with this attachment. Doing so isn't race-free though, as uevents that happen in
                 * the window between this reading of the seqnum, and the LOOP_CONFIGURE call might still be
                 * mistaken as originating from our attachment, even though might be caused by an earlier
                 * use. But doing this at least shortens the race window a bit. */
                r = get_current_uevent_seqnum(&seqnum);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to get the current uevent seqnum: %m");

                timestamp = now(CLOCK_MONOTONIC);

                if (ioctl(fd, LOOP_CONFIGURE, c) < 0) {
                        /* Do fallback only if LOOP_CONFIGURE is not supported, propagate all other
                         * errors. Note that the kernel is weird: non-existing ioctls currently return EINVAL
                         * rather than ENOTTY on loopback block devices. They should fix that in the kernel,
                         * but in the meantime we accept both here. */
                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EINVAL)
                                return log_device_debug_errno(dev, errno, "ioctl(LOOP_CONFIGURE) failed: %m");

                        loop_configure_broken = true;
                } else {
                        loop_with_fd = TAKE_FD(fd);

                        r = loop_configure_verify(loop_with_fd, c);
                        if (r < 0)
                                return log_device_debug_errno(dev, r, "Failed to verify if loopback block device is correctly configured: %m");
                        if (r == 0) {
                                /* LOOP_CONFIGURE doesn't work. Remember that. */
                                loop_configure_broken = true;

                                /* We return EBUSY here instead of retrying immediately with LOOP_SET_FD,
                                 * because LOOP_CLR_FD is async: if the operation cannot be executed right
                                 * away it just sets the autoclear flag on the device. This means there's a
                                 * good chance we cannot actually reuse the loopback device right-away. Hence
                                 * let's assume it's busy, avoid the trouble and let the calling loop call us
                                 * again with a new, likely unused device. */
                                return -EBUSY;
                        }
                }
        }

        if (loop_configure_broken) {
                /* Let's read the seqnum again, to shorten the window. */
                r = get_current_uevent_seqnum(&seqnum);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to get the current uevent seqnum: %m");

                timestamp = now(CLOCK_MONOTONIC);

                if (ioctl(fd, LOOP_SET_FD, c->fd) < 0)
                        return log_device_debug_errno(dev, errno, "ioctl(LOOP_SET_FD) failed: %m");

                loop_with_fd = TAKE_FD(fd);

                r = loop_configure_fallback(loop_with_fd, c);
                if (r < 0)
                        return r;
        }

        r = fd_get_diskseq(loop_with_fd, &diskseq);
        if (r < 0 && r != -EOPNOTSUPP)
                return log_device_debug_errno(dev, r, "Failed to get diskseq: %m");

        switch (lock_op & ~LOCK_NB) {
        case LOCK_EX: /* Already in effect */
                break;
        case LOCK_SH: /* Downgrade */
                if (flock(lock_fd, lock_op) < 0)
                        return log_device_debug_errno(dev, errno, "Failed to downgrade lock level: %m");
                break;
        case LOCK_UN: /* Release */
                lock_fd = safe_close(lock_fd);
                break;
        default:
                assert_not_reached();
        }

        uint64_t device_size;
        r = blockdev_get_device_size(loop_with_fd, &device_size);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get loopback device size: %m");

        LoopDevice *d = new(LoopDevice, 1);
        if (!d)
                return log_oom_debug();

        *d = (LoopDevice) {
                .n_ref = 1,
                .fd = TAKE_FD(loop_with_fd),
                .lock_fd = TAKE_FD(lock_fd),
                .node = TAKE_PTR(node),
                .nr = nr,
                .devno = devno,
                .dev = TAKE_PTR(dev),
                .diskseq = diskseq,
                .uevent_seqnum_not_before = seqnum,
                .timestamp_not_before = timestamp,
                .sector_size = c->block_size,
                .device_size = device_size,
                .created = true,
        };

        *ret = TAKE_PTR(d);
        return 0;
}

static int loop_device_make_internal(
                const char *path,
                int fd,
                int open_flags,
                uint64_t offset,
                uint64_t size,
                uint32_t sector_size,
                uint32_t loop_flags,
                int lock_op,
                LoopDevice **ret) {

        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_close_ int reopened_fd = -EBADF, control = -EBADF;
        _cleanup_free_ char *backing_file = NULL;
        struct loop_config config;
        int r, f_flags;
        struct stat st;

        assert(ret);
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));

        if (fstat(ASSERT_FD(fd), &st) < 0)
                return -errno;

        if (S_ISBLK(st.st_mode)) {
                if (offset == 0 && IN_SET(size, 0, UINT64_MAX))
                        /* If this is already a block device and we are supposed to cover the whole of it
                         * then store an fd to the original open device node — and do not actually create an
                         * unnecessary loopback device for it. */
                        return loop_device_open_from_fd(fd, open_flags, lock_op, ret);
        } else {
                r = stat_verify_regular(&st);
                if (r < 0)
                        return r;
        }

        if (path) {
                r = path_make_absolute_cwd(path, &backing_file);
                if (r < 0)
                        return r;

                path_simplify(backing_file);
        } else {
                r = fd_get_path(fd, &backing_file);
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

                reopened_fd = fd_reopen(fd, (FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO) ? O_DIRECT : 0)|O_CLOEXEC|O_NONBLOCK|open_flags);
                if (reopened_fd < 0) {
                        if (!FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO))
                                return log_debug_errno(reopened_fd, "Failed to reopen file descriptor without O_DIRECT: %m");

                        /* Some file systems might not support O_DIRECT, let's gracefully continue without it then. */
                        log_debug_errno(reopened_fd, "Failed to enable O_DIRECT for backing file descriptor for loopback device. Continuing without.");
                        loop_flags &= ~LO_FLAGS_DIRECT_IO;
                } else
                        fd = reopened_fd; /* From now on, operate on our new O_DIRECT fd */
        }

        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0)
                return -errno;

        if (sector_size == 0)
                /* If no sector size is specified, default to the classic default */
                sector_size = 512;
        else if (sector_size == UINT32_MAX) {

                if (S_ISBLK(st.st_mode))
                        /* If the sector size is specified as UINT32_MAX we'll propagate the sector size of
                         * the underlying block device. */
                        r = blockdev_get_sector_size(fd, &sector_size);
                else {
                        _cleanup_close_ int non_direct_io_fd = -EBADF;
                        int probe_fd;

                        assert(S_ISREG(st.st_mode));

                        /* If sector size is specified as UINT32_MAX, we'll try to probe the right sector
                         * size of the image in question by looking for the GPT partition header at various
                         * offsets. This of course only works if the image already has a disk label.
                         *
                         * So here we actually want to read the file contents ourselves. This is quite likely
                         * not going to work if we managed to enable O_DIRECT, because in such a case there
                         * are some pretty strict alignment requirements to offset, size and target, but
                         * there's no way to query what alignment specifically is actually required. Hence,
                         * let's avoid the mess, and temporarily open an fd without O_DIRECT for the probing
                         * logic. */

                        if (FLAGS_SET(loop_flags, LO_FLAGS_DIRECT_IO)) {
                                non_direct_io_fd = fd_reopen(fd, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                                if (non_direct_io_fd < 0)
                                        return non_direct_io_fd;

                                probe_fd = non_direct_io_fd;
                        } else
                                probe_fd = fd;

                        r = probe_sector_size(probe_fd, &sector_size);
                }
                if (r < 0)
                        return r;
        }

        config = (struct loop_config) {
                .fd = fd,
                .block_size = sector_size,
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
                usec_t usec;
                int nr;

                /* Let's take a lock on the control device first. On a busy system, where many programs
                 * attempt to allocate a loopback device at the same time, we might otherwise keep looping
                 * around relatively heavy operations: asking for a free loopback device, then opening it,
                 * validating it, attaching something to it. Let's serialize this whole operation, to make
                 * unnecessary busywork less likely. Note that this is just something we do to optimize our
                 * own code (and whoever else decides to use LOCK_EX locks for this), taking this lock is not
                 * necessary, it just means it's less likely we have to iterate through this loop again and
                 * again if our own code races against our own code.
                 *
                 * Note: our lock protocol is to take the /dev/loop-control lock first, and the block device
                 * lock second, if both are taken, and always in this order, to avoid ABBA locking issues. */
                if (flock(control, LOCK_EX) < 0)
                        return -errno;

                nr = ioctl(control, LOOP_CTL_GET_FREE);
                if (nr < 0)
                        return -errno;

                r = loop_configure(nr, open_flags, lock_op, &config, &d);
                if (r >= 0)
                        break;

                /* -ENODEV or friends: Somebody might've gotten the same number from the kernel, used the
                 * device, and called LOOP_CTL_REMOVE on it. Let's retry with a new number.
                 * -EBUSY: a file descriptor is already bound to the loopback block device.
                 * -EUCLEAN: some left-over partition devices that were cleaned up.
                 * -ENOANO: we tried to use LO_FLAGS_DIRECT_IO but the kernel rejected it. */
                if (!ERRNO_IS_DEVICE_ABSENT(r) && !IN_SET(r, -EBUSY, -EUCLEAN, -ENOANO))
                        return r;

                /* OK, this didn't work, let's try again a bit later, but first release the lock on the
                 * control device */
                if (flock(control, LOCK_UN) < 0)
                        return -errno;

                if (++n_attempts >= 64) /* Give up eventually */
                        return -EBUSY;

                /* If we failed to enable direct IO mode, let's retry without it. We restart the process as
                 * on some combination of kernel version and storage filesystem, the kernel is very unhappy
                 * about a failed DIRECT_IO enablement and throws I/O errors. */
                if (r == -ENOANO && FLAGS_SET(config.info.lo_flags, LO_FLAGS_DIRECT_IO)) {
                        config.info.lo_flags &= ~LO_FLAGS_DIRECT_IO;
                        open_flags &= ~O_DIRECT;

                        int non_direct_io_fd = fd_reopen(config.fd, O_CLOEXEC|O_NONBLOCK|open_flags);
                        if (non_direct_io_fd < 0)
                                return log_debug_errno(
                                                non_direct_io_fd,
                                                "Failed to reopen file descriptor without O_DIRECT: %m");

                        safe_close(reopened_fd);
                        fd = config.fd = /* For cleanups */ reopened_fd = non_direct_io_fd;
                }

                /* Wait some random time, to make collision less likely. Let's pick a random time in the
                 * range 0ms…250ms, linearly scaled by the number of failed attempts. */
                usec = random_u64_range(UINT64_C(10) * USEC_PER_MSEC +
                                        UINT64_C(240) * USEC_PER_MSEC * n_attempts/64);
                log_debug("Trying again after %s.", FORMAT_TIMESPAN(usec, USEC_PER_MSEC));
                (void) usleep_safe(usec);
        }

        d->backing_file = TAKE_PTR(backing_file);
        d->backing_inode = st.st_ino;
        d->backing_devno = st.st_dev;

        log_debug("Successfully acquired %s, devno=%u:%u, nr=%i, diskseq=%" PRIu64,
                  d->node,
                  major(d->devno), minor(d->devno),
                  d->nr,
                  d->diskseq);

        *ret = TAKE_PTR(d);
        return 0;
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
                uint32_t sector_size,
                uint32_t loop_flags,
                int lock_op,
                LoopDevice **ret) {

        assert(fd >= 0);
        assert(ret);

        return loop_device_make_internal(
                        NULL,
                        fd,
                        open_flags,
                        offset,
                        size,
                        sector_size,
                        loop_flags_mangle(loop_flags),
                        lock_op,
                        ret);
}

int loop_device_make_by_path_at(
                int dir_fd,
                const char *path,
                int open_flags,
                uint32_t sector_size,
                uint32_t loop_flags,
                int lock_op,
                LoopDevice **ret) {

        int r, basic_flags, direct_flags, rdwr_flags;
        _cleanup_close_ int fd = -EBADF;
        bool direct = false;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
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

        fd = xopenat(dir_fd, path, basic_flags|direct_flags|rdwr_flags, /* xopen_flags = */ 0, /* mode = */ 0);
        if (fd < 0 && direct_flags != 0) /* If we had O_DIRECT on, and things failed with that, let's immediately try again without */
                fd = xopenat(dir_fd, path, basic_flags|rdwr_flags, /* xopen_flags = */ 0, /* mode = */ 0);
        else
                direct = direct_flags != 0;
        if (fd < 0) {
                r = -errno;

                /* Retry read-only? */
                if (open_flags >= 0 || !(ERRNO_IS_PRIVILEGE(r) || r == -EROFS))
                        return r;

                fd = xopenat(dir_fd, path, basic_flags|direct_flags|O_RDONLY, /* xopen_flags = */ 0, /* mode = */ 0);
                if (fd < 0 && direct_flags != 0) /* as above */
                        fd = xopenat(dir_fd, path, basic_flags|O_RDONLY, /* xopen_flags = */ 0, /* mode = */ 0);
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

        return loop_device_make_internal(
                        dir_fd == AT_FDCWD ? path : NULL,
                        fd,
                        open_flags,
                        /* offset = */ 0,
                        /* size = */ 0,
                        sector_size,
                        loop_flags,
                        lock_op,
                        ret);
}

int loop_device_make_by_path_memory(
                const char *path,
                int open_flags,
                uint32_t sector_size,
                uint32_t loop_flags,
                int lock_op,
                LoopDevice **ret) {

        _cleanup_close_ int fd = -EBADF, mfd = -EBADF;
        _cleanup_free_ char *fn = NULL;
        struct stat st;
        int r;

        assert(path);
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));
        assert(ret);

        loop_flags &= ~LO_FLAGS_DIRECT_IO; /* memfds don't support O_DIRECT, hence LO_FLAGS_DIRECT_IO can't be used either */

        fd = open(path, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_RDONLY);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))
                return -EBADF;

        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;

        mfd = memfd_clone_fd(fd, fn, open_flags|O_CLOEXEC);
        if (mfd < 0)
                return mfd;

        fd = safe_close(fd); /* Let's close the original early */

        return loop_device_make_internal(NULL, mfd, open_flags, 0, 0, sector_size, loop_flags, lock_op, ret);
}

static LoopDevice* loop_device_free(LoopDevice *d) {
        _cleanup_close_ int control = -EBADF;
        int r;

        if (!d)
                return NULL;

        /* Release any lock we might have on the device first. We want to open+lock the /dev/loop-control
         * device below, but our lock protocol says that if both control and block device locks are taken,
         * the control lock needs to be taken first, the block device lock second — in order to avoid ABBA
         * locking issues. Moreover, we want to issue LOOP_CLR_FD on the block device further down, and that
         * would fail if we had another fd open to the device. */
        d->lock_fd = safe_close(d->lock_fd);

        /* Let's open the control device early, and lock it, so that we can release our block device and
         * delete it in a synchronized fashion, and allocators won't needlessly see the block device as free
         * while we are about to delete it. */
        if (!LOOP_DEVICE_IS_FOREIGN(d) && !d->relinquished) {
                control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (control < 0)
                        log_debug_errno(errno, "Failed to open loop control device, cannot remove loop device '%s', ignoring: %m", strna(d->node));
                else if (flock(control, LOCK_EX) < 0)
                        log_debug_errno(errno, "Failed to lock loop control device, ignoring: %m");
        }

        /* Then let's release the loopback block device */
        if (d->fd >= 0) {
                /* Implicitly sync the device, since otherwise in-flight blocks might not get written */
                if (fsync(d->fd) < 0)
                        log_debug_errno(errno, "Failed to sync loop block device, ignoring: %m");

                if (!LOOP_DEVICE_IS_FOREIGN(d) && !d->relinquished) {
                        /* We are supposed to clear the loopback device. Let's do this synchronously: lock
                         * the device, manually remove all partitions and then clear it. This should ensure
                         * udev doesn't concurrently access the devices, and we can be reasonably sure that
                         * once we are done here the device is cleared and all its partition children
                         * removed. Note that we lock our primary device fd here (and not a separate locking
                         * fd, as we do during allocation, since we want to keep the lock all the way through
                         * the LOOP_CLR_FD, but that call would fail if we had more than one fd open.) */

                        if (flock(d->fd, LOCK_EX) < 0)
                                log_debug_errno(errno, "Failed to lock loop block device, ignoring: %m");

                        r = block_device_remove_all_partitions(d->dev, d->fd);
                        if (r < 0)
                                log_debug_errno(r, "Failed to remove partitions of loopback block device, ignoring: %m");

                        if (ioctl(d->fd, LOOP_CLR_FD) < 0)
                                log_debug_errno(errno, "Failed to clear loop device, ignoring: %m");
                }

                safe_close(d->fd);
        }

        /* Now that the block device is released, let's also try to remove it */
        if (control >= 0) {
                useconds_t delay = 5 * USEC_PER_MSEC;  /* A total delay of 5090 ms between 39 attempts,
                                                        * (4*5 + 5*10 + 5*20 + … + 3*640) = 5090. */

                for (unsigned attempt = 1;; attempt++) {
                        if (ioctl(control, LOOP_CTL_REMOVE, d->nr) >= 0)
                                break;
                        if (errno != EBUSY || attempt > 38) {
                                log_debug_errno(errno, "Failed to remove device %s: %m", strna(d->node));
                                break;
                        }
                        if (attempt % 5 == 0) {
                                log_debug("Device is still busy after %u attempts…", attempt);
                                delay *= 2;
                        }

                        (void) usleep_safe(delay);
                }
        }

        free(d->node);
        sd_device_unref(d->dev);
        free(d->backing_file);
        return mfree(d);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(LoopDevice, loop_device, loop_device_free);

void loop_device_relinquish(LoopDevice *d) {
        assert(d);

        /* Don't attempt to clean up the loop device anymore from this point on. Leave the clean-ing up to the kernel
         * itself, using the loop device "auto-clear" logic we already turned on when creating the device. */

        d->relinquished = true;
}

void loop_device_unrelinquish(LoopDevice *d) {
        assert(d);
        d->relinquished = false;
}

int loop_device_open(
                sd_device *dev,
                int open_flags,
                int lock_op,
                LoopDevice **ret) {

        _cleanup_close_ int fd = -EBADF, lock_fd = -EBADF;
        _cleanup_free_ char *node = NULL, *backing_file = NULL;
        dev_t devnum, backing_devno = 0;
        struct loop_info64 info;
        ino_t backing_inode = 0;
        uint64_t diskseq = 0;
        LoopDevice *d;
        const char *s;
        int r, nr = -1;

        assert(dev);
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));
        assert(ret);

        /* Even if fd is provided through the argument in loop_device_open_from_fd(), we reopen the inode
         * here, instead of keeping just a dup() clone of it around, since we want to ensure that the
         * O_DIRECT flag of the handle we keep is off, we have our own file index, and have the right
         * read/write mode in effect. */
        fd = sd_device_open(dev, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|open_flags);
        if (fd < 0)
                return fd;

        if ((lock_op & ~LOCK_NB) != LOCK_UN) {
                lock_fd = open_lock_fd(fd, lock_op);
                if (lock_fd < 0)
                        return lock_fd;
        }

        if (ioctl(fd, LOOP_GET_STATUS64, &info) >= 0) {
#if HAVE_VALGRIND_MEMCHECK_H
                /* Valgrind currently doesn't know LOOP_GET_STATUS64. Remove this once it does */
                VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif
                nr = info.lo_number;

                if (sd_device_get_sysattr_value(dev, "loop/backing_file", &s) >= 0) {
                        backing_file = strdup(s);
                        if (!backing_file)
                                return -ENOMEM;
                }

                backing_devno = info.lo_device;
                backing_inode = info.lo_inode;
        }

        r = fd_get_diskseq(fd, &diskseq);
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        uint32_t sector_size;
        r = blockdev_get_sector_size(fd, &sector_size);
        if (r < 0)
                return r;

        uint64_t device_size;
        r = blockdev_get_device_size(fd, &device_size);
        if (r < 0)
                return r;

        r = sd_device_get_devnum(dev, &devnum);
        if (r < 0)
                return r;

        r = sd_device_get_devname(dev, &s);
        if (r < 0)
                return r;

        node = strdup(s);
        if (!node)
                return -ENOMEM;

        d = new(LoopDevice, 1);
        if (!d)
                return -ENOMEM;

        *d = (LoopDevice) {
                .n_ref = 1,
                .fd = TAKE_FD(fd),
                .lock_fd = TAKE_FD(lock_fd),
                .nr = nr,
                .node = TAKE_PTR(node),
                .dev = sd_device_ref(dev),
                .backing_file = TAKE_PTR(backing_file),
                .backing_inode = backing_inode,
                .backing_devno = backing_devno,
                .relinquished = true, /* It's not ours, don't try to destroy it when this object is freed */
                .devno = devnum,
                .diskseq = diskseq,
                .uevent_seqnum_not_before = UINT64_MAX,
                .timestamp_not_before = USEC_INFINITY,
                .sector_size = sector_size,
                .device_size = device_size,
                .created = false,
        };

        *ret = d;
        return 0;
}

int loop_device_open_from_fd(
                int fd,
                int open_flags,
                int lock_op,
                LoopDevice **ret) {

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        r = block_device_new_from_fd(ASSERT_FD(fd), 0, &dev);
        if (r < 0)
                return r;

        return loop_device_open(dev, open_flags, lock_op, ret);
}

int loop_device_open_from_path(
                const char *path,
                int open_flags,
                int lock_op,
                LoopDevice **ret) {

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(path);

        r = block_device_new_from_path(path, 0, &dev);
        if (r < 0)
                return r;

        return loop_device_open(dev, open_flags, lock_op, ret);
}

static int resize_partition(int partition_fd, uint64_t offset, uint64_t size) {
        char sysfs[STRLEN("/sys/dev/block/:/partition") + 2*DECIMAL_STR_MAX(dev_t) + 1];
        _cleanup_free_ char *buffer = NULL;
        uint64_t current_offset, current_size, partno;
        _cleanup_close_ int whole_fd = -EBADF;
        struct stat st;
        dev_t devno;
        int r;

        /* Resizes the partition the loopback device refer to (assuming it refers to one instead of an actual
         * loopback device), and changes the offset, if needed. This is a fancy wrapper around
         * BLKPG_RESIZE_PARTITION. */

        if (fstat(ASSERT_FD(partition_fd), &st) < 0)
                return -errno;

        assert(S_ISBLK(st.st_mode));

        xsprintf(sysfs, "/sys/dev/block/" DEVNUM_FORMAT_STR "/partition", DEVNUM_FORMAT_VAL(st.st_rdev));
        r = read_one_line_file(sysfs, &buffer);
        if (r == -ENOENT) /* not a partition, cannot resize */
                return -ENOTTY;
        if (r < 0)
                return r;
        r = safe_atou64(buffer, &partno);
        if (r < 0)
                return r;

        xsprintf(sysfs, "/sys/dev/block/" DEVNUM_FORMAT_STR "/start", DEVNUM_FORMAT_VAL(st.st_rdev));

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

        r = blockdev_get_device_size(partition_fd, &current_size);
        if (r < 0)
                return r;

        if (size == UINT64_MAX && offset == UINT64_MAX)
                return 0;
        if (current_size == size && current_offset == offset)
                return 0;

        xsprintf(sysfs, "/sys/dev/block/" DEVNUM_FORMAT_STR "/../dev", DEVNUM_FORMAT_VAL(st.st_rdev));

        buffer = mfree(buffer);
        r = read_one_line_file(sysfs, &buffer);
        if (r < 0)
                return r;
        r = parse_devnum(buffer, &devno);
        if (r < 0)
                return r;

        whole_fd = r = device_open_from_devnum(S_IFBLK, devno, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, NULL);
        if (r < 0)
                return r;

        return block_device_resize_partition(
                        whole_fd,
                        partno,
                        offset == UINT64_MAX ? current_offset : offset,
                        size == UINT64_MAX ? current_size : size);
}

int loop_device_refresh_size(LoopDevice *d, uint64_t offset, uint64_t size) {
        struct loop_info64 info;

        assert(d);
        assert(d->fd >= 0);

        /* Changes the offset/start of the loop device relative to the beginning of the underlying file or
         * block device. If this loop device actually refers to a partition and not a loopback device, we'll
         * try to adjust the partition offsets instead.
         *
         * If either offset or size is UINT64_MAX we won't change that parameter. */

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
        assert(IN_SET(operation & ~LOCK_NB, LOCK_UN, LOCK_SH, LOCK_EX));
        assert(d);

        /* When unlocking just close the lock fd */
        if ((operation & ~LOCK_NB) == LOCK_UN) {
                d->lock_fd = safe_close(d->lock_fd);
                return 0;
        }

        /* If we had no lock fd so far, create one and lock it right-away */
        if (d->lock_fd < 0) {
                d->lock_fd = open_lock_fd(ASSERT_FD(d->fd), operation);
                if (d->lock_fd < 0)
                        return d->lock_fd;

                return 0;
        }

        /* Otherwise change the current lock mode on the existing fd */
        return RET_NERRNO(flock(d->lock_fd, operation));
}

int loop_device_sync(LoopDevice *d) {
        assert(d);

        /* We also do this implicitly in loop_device_unref(). Doing this explicitly here has the benefit that
         * we can check the return value though. */

        return RET_NERRNO(fsync(ASSERT_FD(d->fd)));
}

int loop_device_set_autoclear(LoopDevice *d, bool autoclear) {
        struct loop_info64 info;

        assert(d);

        if (ioctl(ASSERT_FD(d->fd), LOOP_GET_STATUS64, &info) < 0)
                return -errno;

        if (autoclear == FLAGS_SET(info.lo_flags, LO_FLAGS_AUTOCLEAR))
                return 0;

        SET_FLAG(info.lo_flags, LO_FLAGS_AUTOCLEAR, autoclear);

        if (ioctl(d->fd, LOOP_SET_STATUS64, &info) < 0)
                return -errno;

        return 1;
}

int loop_device_set_filename(LoopDevice *d, const char *name) {
        struct loop_info64 info;

        assert(d);

        /* Sets the .lo_file_name of the loopback device. This is supposed to contain the path to the file
         * backing the block device, but is actually just a free-form string you can pass to the kernel. Most
         * tools that actually care for the backing file path use the sysfs attribute file loop/backing_file
         * which is a kernel generated string, subject to file system namespaces and such.
         *
         * .lo_file_name is useful since userspace can select it freely when creating a loopback block
         * device, and we can use it for /dev/disk/by-loop-ref/ symlinks, and similar, so that apps can
         * recognize their own loopback files. */

        if (name && strlen(name) >= sizeof(info.lo_file_name))
                return -ENOBUFS;

        if (ioctl(ASSERT_FD(d->fd), LOOP_GET_STATUS64, &info) < 0)
                return -errno;

        if (strneq((char*) info.lo_file_name, strempty(name), sizeof(info.lo_file_name)))
                return 0;

        if (name) {
                strncpy((char*) info.lo_file_name, name, sizeof(info.lo_file_name)-1);
                info.lo_file_name[sizeof(info.lo_file_name)-1] = 0;
        } else
                memzero(info.lo_file_name, sizeof(info.lo_file_name));

        if (ioctl(d->fd, LOOP_SET_STATUS64, &info) < 0)
                return -errno;

        return 1;
}
