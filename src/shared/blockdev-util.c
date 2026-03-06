/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/blkpg.h>
#include <linux/fs.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "device-private.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"

static int fd_get_devnum(int fd, BlockDeviceLookupFlags flags, dev_t *ret) {
        struct stat st;
        dev_t devnum;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISBLK(st.st_mode))
                devnum = st.st_rdev;
        else if (!FLAGS_SET(flags, BLOCK_DEVICE_LOOKUP_BACKING))
                return -ENOTBLK;
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
                return -ENOTBLK;
        else if (major(st.st_dev) != 0)
                devnum = st.st_dev;
        else {
                /* If major(st.st_dev) is zero, this might mean we are backed by btrfs, which needs special
                 * handing, to get the backing device node. */

                r = btrfs_get_block_device_fd(fd, &devnum);
                if (r == -ENOTTY) /* not btrfs */
                        return -ENOTBLK;
                if (r < 0)
                        return r;
        }

        *ret = devnum;
        return 0;
}

int block_device_is_whole_disk(sd_device *dev) {
        int r;

        assert(dev);

        r = device_in_subsystem(dev, "block");
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTBLK;

        return device_is_devtype(dev, "disk");
}

int block_device_get_whole_disk(sd_device *dev, sd_device **ret) {
        int r;

        assert(dev);
        assert(ret);

        /* Do not unref returned sd_device object. */

        r = block_device_is_whole_disk(dev);
        if (r < 0)
                return r;
        if (r == 0) {
                r = sd_device_get_parent(dev, &dev);
                if (r == -ENOENT) /* Already removed? Let's return a recognizable error. */
                        return -ENODEV;
                if (r < 0)
                        return r;

                r = block_device_is_whole_disk(dev);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENXIO;
        }

        *ret = dev;
        return 0;
}

static int block_device_get_originating_one(sd_device *dev, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *first_found = NULL;
        const char *suffix;
        dev_t devnum = 0;  /* avoid false maybe-uninitialized warning */

        /* For the specified block device tries to chase it through the layers, in case LUKS-style DM
         * stacking is used, trying to find the next underlying layer. */

        assert(dev);
        assert(ret);

        FOREACH_DEVICE_CHILD_WITH_SUFFIX(dev, child, suffix) {
                sd_device *child_whole_disk;
                dev_t n;

                if (!path_startswith(suffix, "slaves"))
                        continue;

                if (block_device_get_whole_disk(child, &child_whole_disk) < 0)
                        continue;

                if (sd_device_get_devnum(child_whole_disk, &n) < 0)
                        continue;

                if (!first_found) {
                        first_found = sd_device_ref(child);
                        devnum = n;
                        continue;
                }

                /* We found a device backed by multiple other devices. We don't really support automatic
                 * discovery on such setups, with the exception of dm-verity partitions. In this case there
                 * are two backing devices: the data partition and the hash partition. We are fine with such
                 * setups, however, only if both partitions are on the same physical device. Hence, let's
                 * verify this by iterating over every node in the 'slaves/' directory and comparing them with
                 * the first that gets returned by readdir(), to ensure they all point to the same device. */
                if (n != devnum)
                        return -ENOTUNIQ;
        }

        if (!first_found)
                return -ENOENT;

        *ret = TAKE_PTR(first_found);
        return 0;
}

int block_device_get_originating(sd_device *dev, sd_device **ret, bool recursive) {
        _cleanup_(sd_device_unrefp) sd_device *current = NULL;
        int r;

        assert(dev);
        assert(ret);

        if (!recursive)
                return block_device_get_originating_one(dev, ret);

        current = sd_device_ref(dev);

        for (;;) {
                sd_device *origin;

                r = block_device_get_originating_one(current, &origin);
                if (r == -ENOENT)
                        break;
                if (r < 0)
                        return r;

                sd_device_unref(current);
                current = origin;
        }

        if (current == dev)
                return -ENOENT;

        *ret = TAKE_PTR(current);

        return 0;
}

int block_device_new_from_fd(int fd, BlockDeviceLookupFlags flags, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        dev_t devnum;
        int r;

        assert(fd >= 0);
        assert(ret);

        r = fd_get_devnum(fd, flags, &devnum);
        if (r < 0)
                return r;

        r = sd_device_new_from_devnum(&dev, 'b', devnum);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, BLOCK_DEVICE_LOOKUP_ORIGINATING)) {
                _cleanup_(sd_device_unrefp) sd_device *dev_origin = NULL;
                sd_device *dev_whole_disk;

                r = block_device_get_whole_disk(dev, &dev_whole_disk);
                if (r < 0)
                        return r;

                r = block_device_get_originating(dev_whole_disk, &dev_origin, /* recursive= */ false);
                if (r >= 0)
                        device_unref_and_replace(dev, dev_origin);
                else if (r != -ENOENT)
                        return r;
        }

        if (FLAGS_SET(flags, BLOCK_DEVICE_LOOKUP_WHOLE_DISK)) {
                sd_device *dev_whole_disk;

                r = block_device_get_whole_disk(dev, &dev_whole_disk);
                if (r < 0)
                        return r;

                *ret = sd_device_ref(dev_whole_disk);
                return 0;
        }

        *ret = sd_device_ref(dev);
        return 0;
}

int block_device_new_from_path(const char *path, BlockDeviceLookupFlags flags, sd_device **ret) {
        _cleanup_close_ int fd = -EBADF;

        assert(path);
        assert(ret);

        fd = open(path, O_CLOEXEC|O_PATH);
        if (fd < 0)
                return -errno;

        return block_device_new_from_fd(fd, flags, ret);
}

int block_get_whole_disk(dev_t d, dev_t *ret) {
        char p[SYS_BLOCK_PATH_MAX("/partition")];
        _cleanup_free_ char *s = NULL;
        dev_t devt;
        int r;

        assert(ret);

        if (major(d) == 0)
                return -ENODEV;

        /* If it has a queue this is good enough for us */
        xsprintf_sys_block_path(p, "/queue", d);
        if (access(p, F_OK) >= 0) {
                *ret = d;
                return 0;
        }
        if (errno != ENOENT)
                return -errno;

        /* If it is a partition find the originating device */
        xsprintf_sys_block_path(p, "/partition", d);
        if (access(p, F_OK) < 0)
                return -errno;

        /* Get parent dev_t */
        xsprintf_sys_block_path(p, "/../dev", d);
        r = read_one_line_file(p, &s);
        if (r < 0)
                return r;

        r = parse_devnum(s, &devt);
        if (r < 0)
                return r;

        /* Only return this if it is really good enough for us. */
        xsprintf_sys_block_path(p, "/queue", devt);
        if (access(p, F_OK) < 0)
                return -errno;

        *ret = devt;
        return 1;
}

int get_block_device_fd(int fd, dev_t *ret) {
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Gets the block device directly backing a file system. If the block device is encrypted, returns
         * the device mapper block device. */

        if (fstat(fd, &st))
                return -errno;

        if (major(st.st_dev) != 0) {
                *ret = st.st_dev;
                return 1;
        }

        r = btrfs_get_block_device_fd(fd, ret);
        if (r != -ENOTTY) /* ENOTTY: not btrfs */
                return r;

        *ret = 0;
        return 0;
}

int get_block_device(const char *path, dev_t *ret) {
        _cleanup_close_ int fd = -EBADF;

        assert(path);
        assert(ret);

        fd = open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return get_block_device_fd(fd, ret);
}

int block_get_originating(dev_t dt, dev_t *ret, bool recursive) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL, *origin = NULL;
        int r;

        assert(ret);

        r = sd_device_new_from_devnum(&dev, 'b', dt);
        if (r < 0)
                return r;

        r = block_device_get_originating(dev, &origin, recursive);
        if (r < 0)
                return r;

        return sd_device_get_devnum(origin, ret);
}

int get_block_device_harder_fd(int fd, dev_t *ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Gets the backing block device for a file system, and handles LUKS encrypted file systems, looking
         * for its underlying physical device, if there is one. */

        r = get_block_device_fd(fd, ret);
        if (r <= 0)
                return r;

        r = block_get_originating(*ret, ret, /* recursive= */ true);
        if (r < 0)
                log_debug_errno(r, "Failed to chase block device, ignoring: %m");

        return 1;
}

int get_block_device_harder(const char *path, dev_t *ret) {
        _cleanup_close_ int fd = -EBADF;

        assert(path);
        assert(ret);

        fd = open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return get_block_device_harder_fd(fd, ret);
}

int lock_whole_block_device(dev_t devt, int open_flags, int operation) {
        _cleanup_close_ int lock_fd = -EBADF;
        dev_t whole_devt;
        int r;

        /* Let's get a BSD file lock on the whole block device, as per: https://systemd.io/BLOCK_DEVICE_LOCKING
         *
         * NB: it matters whether open_flags indicates open for write: only then will the eventual closing of
         * the fd trigger udev's partitioning rescanning of the device (as it watches for IN_CLOSE_WRITE),
         * hence make sure to pass the right value there. */

        r = block_get_whole_disk(devt, &whole_devt);
        if (r < 0)
                return r;

        lock_fd = device_open_from_devnum(S_IFBLK, whole_devt, open_flags|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, NULL);
        if (lock_fd < 0)
                return lock_fd;

        if (flock(lock_fd, operation) < 0)
                return -errno;

        return TAKE_FD(lock_fd);
}

int blockdev_partscan_enabled(sd_device *dev) {
        unsigned capability;
        int r, ext_range;

        /* Checks if partition scanning is correctly enabled on the block device.
         *
         * The 'GENHD_FL_NO_PART_SCAN' flag was introduced by
         * https://github.com/torvalds/linux/commit/d27769ec3df1a8de9ca450d2dcd72d1ab259ba32 (v3.2).
         * But at that time, the flag is also effectively implied when 'minors' element of 'struct gendisk'
         * is 1, which can be check with 'ext_range' sysfs attribute. Explicit flag ('GENHD_FL_NO_PART_SCAN')
         * can be obtained from 'capability' sysattr.
         *
         * With https://github.com/torvalds/linux/commit/46e7eac647b34ed4106a8262f8bedbb90801fadd (v5.17),
         * the flag is renamed to GENHD_FL_NO_PART.
         *
         * With https://github.com/torvalds/linux/commit/1ebe2e5f9d68e94c524aba876f27b945669a7879 (v5.17),
         * we can check the flag from 'ext_range' sysfs attribute directly.
         *
         * With https://github.com/torvalds/linux/commit/430cc5d3ab4d0ba0bd011cfbb0035e46ba92920c (v5.17),
         * the value of GENHD_FL_NO_PART is changed from 0x0200 to 0x0004. 💣💣💣
         * Note, the new value was used by the GENHD_FL_MEDIA_CHANGE_NOTIFY flag, which was introduced by
         * 86ce18d7b7925bfd6b64c061828ca2a857ee83b8 (v2.6.22), and removed by
         * 9243c6f3e012a92dd900d97ef45efaf8a8edc448 (v5.7). If we believe the commit message of
         * e81cd5a983bb35dabd38ee472cf3fea1c63e0f23, the flag was never used. So, fortunately, we can use
         * both the new and old values safely.
         *
         * With https://github.com/torvalds/linux/commit/b9684a71fca793213378dd410cd11675d973eaa1 (v5.19),
         * another flag GD_SUPPRESS_PART_SCAN is introduced for loopback block device, and partition scanning
         * is done only when both GENHD_FL_NO_PART and GD_SUPPRESS_PART_SCAN are not set. Before the commit,
         * LO_FLAGS_PARTSCAN flag was directly tied with GENHD_FL_NO_PART. But with this change now it is
         * tied with GD_SUPPRESS_PART_SCAN. So, LO_FLAGS_PARTSCAN cannot be obtained from 'ext_range'
         * sysattr, which corresponds to GENHD_FL_NO_PART, and we need to read 'loop/partscan'. 💣💣💣
         *
         * With https://github.com/torvalds/linux/commit/73a166d9749230d598320fdae3b687cdc0e2e205 (v6.3),
         * the GD_SUPPRESS_PART_SCAN flag is also introduced for userspace block device (ublk). Though, not
         * sure if we should support the device...
         *
         * With https://github.com/torvalds/linux/commit/e81cd5a983bb35dabd38ee472cf3fea1c63e0f23 (v6.3),
         * the 'capability' sysfs attribute is deprecated, hence we cannot check flags from it. 💣💣💣
         *
         * With https://github.com/torvalds/linux/commit/a4217c6740dc64a3eb6815868a9260825e8c68c6 (v6.10,
         * backported to v6.6+), the partscan status is directly exposed as 'partscan' sysattr.
         *
         * To support both old and new kernels, we need to do the following:
         * 1) check 'partscan' sysfs attribute where the information is made directly available,
         * 2) check if the blockdev refers to a partition, where partscan is not supported,
         * 3) check 'loop/partscan' sysfs attribute for loopback block devices, and if '0' we can conclude
         *    partition scanning is disabled,
         * 4) check 'ext_range' sysfs attribute, and if '1' we can conclude partition scanning is disabled,
         * 5) otherwise check 'capability' sysfs attribute for ancient version. */

        assert(dev);

        r = device_in_subsystem(dev, "block");
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTBLK;

        /* For v6.10 or newer. */
        r = device_get_sysattr_bool(dev, "partscan");
        if (r != -ENOENT)
                return r;

        /* Partition block devices never have partition scanning on, there's no concept of sub-partitions for
         * partitions. */
        r = device_is_devtype(dev, "partition");
        if (r < 0)
                return r;
        if (r > 0)
                return false;

        /* For loopback block device, especially for v5.19 or newer. Even if this is enabled, we also need to
         * check GENHD_FL_NO_PART flag through 'ext_range' and 'capability' sysfs attributes below. */
        if (device_get_sysattr_bool(dev, "loop/partscan") == 0)
                return false;

        r = device_get_sysattr_int(dev, "ext_range", &ext_range);
        if (r == -ENOENT) /* If the ext_range file doesn't exist then we are most likely looking at a
                           * partition block device, not the whole block device. And that means we have no
                           * partition scanning on for it (we do for its parent, but not for the partition
                           * itself). */
                return false;
        if (r < 0)
                return r;

        if (ext_range <= 1) /* The value should be always positive, but the kernel uses '%d' for the
                             * attribute. Let's gracefully handle zero or negative. */
                return false;

        r = device_get_sysattr_unsigned_full(dev, "capability", 16, &capability);
        if (r == -ENOENT)
                return false;
        if (r < 0)
                return r;

#define GENHD_FL_NO_PART_OLD 0x0200
#define GENHD_FL_NO_PART_NEW 0x0004
        /* If one of the NO_PART flags is set, part scanning is definitely off. */
        if ((capability & (GENHD_FL_NO_PART_OLD | GENHD_FL_NO_PART_NEW)) != 0)
                return false;

        /* Otherwise, assume part scanning is on, we have no further checks available. Assume the best. */
        return true;
}

int blockdev_partscan_enabled_fd(int fd) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(fd >= 0);

        r = block_device_new_from_fd(fd, 0, &dev);
        if (r < 0)
                return r;

        return blockdev_partscan_enabled(dev);
}

static int blockdev_is_encrypted(const char *sysfs_path, unsigned depth_left) {
        _cleanup_free_ char *p = NULL, *uuids = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r, found_encrypted = false;

        assert(sysfs_path);

        if (depth_left == 0)
                return -EINVAL;

        p = path_join(sysfs_path, "dm/uuid");
        if (!p)
                return -ENOMEM;

        r = read_one_line_file(p, &uuids);
        if (r != -ENOENT) {
                if (r < 0)
                        return r;

                /* The DM device's uuid attribute is prefixed with "CRYPT-" if this is a dm-crypt device. */
                if (startswith(uuids, "CRYPT-"))
                        return true;
        }

        /* Not a dm-crypt device itself. But maybe it is on top of one? Follow the links in the "slaves/"
         * subdir. */

        p = mfree(p);
        p = path_join(sysfs_path, "slaves");
        if (!p)
                return -ENOMEM;

        d = opendir(p);
        if (!d) {
                if (errno == ENOENT) /* Doesn't have underlying devices */
                        return false;

                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *q = NULL;
                struct dirent *de;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                return -errno;

                        break; /* No more underlying devices */
                }

                q = path_join(p, de->d_name);
                if (!q)
                        return -ENOMEM;

                r = blockdev_is_encrypted(q, depth_left - 1);
                if (r < 0)
                        return r;
                if (r == 0) /* we found one that is not encrypted? then propagate that immediately */
                        return false;

                found_encrypted = true;
        }

        return found_encrypted;
}

int fd_is_encrypted(int fd) {
        char p[SYS_BLOCK_PATH_MAX("")];
        dev_t devt;
        int r;

        r = get_block_device_fd(fd, &devt);
        if (r < 0)
                return r;
        if (r == 0) /* doesn't have a block device */
                return false;

        xsprintf_sys_block_path(p, NULL, devt);

        return blockdev_is_encrypted(p, 10 /* safety net: maximum recursion depth */);
}

int path_is_encrypted(const char *path) {
        char p[SYS_BLOCK_PATH_MAX("")];
        dev_t devt;
        int r;

        r = get_block_device(path, &devt);
        if (r < 0)
                return r;
        if (r == 0) /* doesn't have a block device */
                return false;

        xsprintf_sys_block_path(p, NULL, devt);

        return blockdev_is_encrypted(p, 10 /* safety net: maximum recursion depth */);
}

int fd_get_whole_disk(int fd, bool backing, dev_t *ret) {
        dev_t devt;
        int r;

        assert(fd >= 0);
        assert(ret);

        r = fd_get_devnum(fd, backing ? BLOCK_DEVICE_LOOKUP_BACKING : 0, &devt);
        if (r < 0)
                return r;

        return block_get_whole_disk(devt, ret);
}

int path_get_whole_disk(const char *path, bool backing, dev_t *ret) {
        _cleanup_close_ int fd = -EBADF;

        fd = open(path, O_CLOEXEC|O_PATH);
        if (fd < 0)
                return -errno;

        return fd_get_whole_disk(fd, backing, ret);
}

int block_device_add_partition(
                int fd,
                const char *name,
                int nr,
                uint64_t start,
                uint64_t size) {

        assert(fd >= 0);
        assert(name);
        assert(nr > 0);

        struct blkpg_partition bp = {
                .pno = nr,
                .start = start,
                .length = size,
        };

        struct blkpg_ioctl_arg ba = {
                .op = BLKPG_ADD_PARTITION,
                .data = &bp,
                .datalen = sizeof(bp),
        };

        if (strlen(name) >= sizeof(bp.devname))
                return -EINVAL;

        strcpy(bp.devname, name);

        return RET_NERRNO(ioctl(fd, BLKPG, &ba));
}

int block_device_remove_partition(
                int fd,
                const char *name,
                int nr) {

        assert(fd >= 0);
        assert(name);
        assert(nr > 0);

        struct blkpg_partition bp = {
                .pno = nr,
        };

        struct blkpg_ioctl_arg ba = {
                .op = BLKPG_DEL_PARTITION,
                .data = &bp,
                .datalen = sizeof(bp),
        };

        if (strlen(name) >= sizeof(bp.devname))
                return -EINVAL;

        strcpy(bp.devname, name);

        return RET_NERRNO(ioctl(fd, BLKPG, &ba));
}

int block_device_resize_partition(
                int fd,
                int nr,
                uint64_t start,
                uint64_t size) {

        assert(fd >= 0);
        assert(nr > 0);

        struct blkpg_partition bp = {
                .pno = nr,
                .start = start,
                .length = size,
        };

        struct blkpg_ioctl_arg ba = {
                .op = BLKPG_RESIZE_PARTITION,
                .data = &bp,
                .datalen = sizeof(bp),
        };

        return RET_NERRNO(ioctl(fd, BLKPG, &ba));
}

int partition_enumerator_new(sd_device *dev, sd_device_enumerator **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        const char *s;
        int r;

        assert(dev);
        assert(ret);

        /* Refuse invocation on partition block device, insist on "whole" device */
        r = block_device_is_whole_disk(dev);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENXIO; /* return a recognizable error */

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_parent(e, dev);
        if (r < 0)
                return r;

        r = sd_device_get_sysname(dev, &s);
        if (r < 0)
                return r;

        /* Also add sysname check for safety. Hopefully, this also improves performance. */
        s = strjoina(s, "*");
        r = sd_device_enumerator_add_match_sysname(e, s);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "block", /* match= */ true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_property(e, "DEVTYPE", "partition");
        if (r < 0)
                return r;

        *ret = TAKE_PTR(e);
        return 0;
}

int block_device_remove_all_partitions(sd_device *dev, int fd) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev_unref = NULL;
        _cleanup_close_ int fd_close = -EBADF;
        bool has_partitions = false;
        int r, k = 0;

        assert(dev || fd >= 0);

        if (!dev) {
                r = block_device_new_from_fd(fd, 0, &dev_unref);
                if (r < 0)
                        return r;

                dev = dev_unref;
        }

        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return r;

        if (fd < 0) {
                fd_close = sd_device_open(dev, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_RDONLY);
                if (fd_close < 0)
                        return fd_close;

                fd = fd_close;
        }

        FOREACH_DEVICE(e, part) {
                const char *v, *devname;
                int nr;

                has_partitions = true;

                r = sd_device_get_devname(part, &devname);
                if (r < 0)
                        return r;

                r = sd_device_get_property_value(part, "PARTN", &v);
                if (r < 0)
                        return r;

                r = safe_atoi(v, &nr);
                if (r < 0)
                        return r;

                r = btrfs_forget_device(devname);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to forget btrfs device %s, ignoring: %m", devname);

                r = block_device_remove_partition(fd, devname, nr);
                if (r == -ENODEV) {
                        log_debug("Kernel removed partition %s before us, ignoring", devname);
                        continue;
                }
                if (r < 0) {
                        log_debug_errno(r, "Failed to remove partition %s: %m", devname);
                        k = k < 0 ? k : r;
                        continue;
                }

                log_debug("Removed partition %s", devname);
        }

        return k < 0 ? k : has_partitions;
}

int blockdev_get_sector_size(int fd, uint32_t *ret) {
        int ssz = 0;

        assert(fd >= 0);
        assert(ret);

        if (ioctl(fd, BLKSSZGET, &ssz) < 0)
                return -errno;
        if (ssz <= 0) /* make sure the field is initialized */
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Block device reported invalid sector size %i.", ssz);

        *ret = ssz;
        return 0;
}

int blockdev_get_device_size(int fd, uint64_t *ret) {
        uint64_t sz = 0;

        assert(fd >= 0);
        assert(ret);

        /* This is just a type-safe wrapper around BLKGETSIZE64 that gets us around having to include messy linux/fs.h in various clients */

        if (ioctl(fd, BLKGETSIZE64, &sz) < 0)
                return -errno;

        *ret = sz;
        return 0;
}

int blockdev_get_root(int level, dev_t *ret) {
        _cleanup_free_ char *p = NULL;
        dev_t devno;
        int r;

        /* Returns the device node backing the root file system. Traces through
         * dm-crypt/dm-verity/... Returns > 0 and the devno of the device on success. If there's no block
         * device (or multiple) returns 0 and a devno of 0. Failure otherwise.
         *
         * If the root mount has been replaced by some form of volatile file system (overlayfs), the original
         * root block device node is symlinked in /run/systemd/volatile-root. Let's read that here. */
        r = readlink_malloc("/run/systemd/volatile-root", &p);
        if (r == -ENOENT) { /* volatile-root not found */
                r = get_block_device_harder("/", &devno);
                if (r == -EUCLEAN)
                        return btrfs_log_dev_root(level, r, "root file system");
                if (r < 0)
                        return log_full_errno(level, r, "Failed to determine block device of root file system: %m");
                if (r == 0) { /* Not backed by a single block device. (Could be NFS or so, or could be multi-device RAID or so) */
                        r = get_block_device_harder("/usr", &devno);
                        if (r == -EUCLEAN)
                                return btrfs_log_dev_root(level, r, "/usr");
                        if (r < 0)
                                return log_full_errno(level, r, "Failed to determine block device of /usr/ file system: %m");
                        if (r == 0) { /* /usr/ not backed by single block device, either. */
                                log_debug("Neither root nor /usr/ file system are on a (single) block device.");

                                if (ret)
                                        *ret = 0;

                                return 0;
                        }
                }
        } else if (r < 0)
                return log_full_errno(level, r, "Failed to read symlink /run/systemd/volatile-root: %m");
        else {
                mode_t m;
                r = device_path_parse_major_minor(p, &m, &devno);
                if (r < 0)
                        return log_full_errno(level, r, "Failed to parse major/minor device node: %m");
                if (!S_ISBLK(m))
                        return log_full_errno(level, SYNTHETIC_ERRNO(ENOTBLK), "Volatile root device is of wrong type.");
        }

        if (ret)
                *ret = devno;

        return 1;
}

int partition_node_of(const char *node, unsigned nr, char **ret) {
        _cleanup_free_ char *fn = NULL, *dn = NULL;
        int r;

        assert(node);
        assert(nr > 0);
        assert(ret);

        /* Given a device node path to a block device returns the device node path to the partition block
         * device of the specified partition */

        r = path_split_prefix_filename(node, &dn, &fn);
        if (r < 0)
                return r;
        if (r == O_DIRECTORY)
                return -EISDIR;

        size_t l = strlen(fn);
        assert(l > 0); /* underflow check for the subtraction below */

        bool need_p = ascii_isdigit(fn[l-1]); /* Last char a digit? */

        _cleanup_free_ char *subnode = NULL;
        if (asprintf(&subnode, "%s%s%u", fn, need_p ? "p" : "", nr) < 0)
                return -ENOMEM;

        if (dn) {
                _cleanup_free_ char *j = path_join(dn, subnode);
                if (!j)
                        return -ENOMEM;

                *ret = TAKE_PTR(j);
        } else
                *ret = TAKE_PTR(subnode);

        return 0;
}
