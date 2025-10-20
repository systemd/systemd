/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fs.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "device-private.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "parse-util.h"
#include "rereadpt.h"
#include "set.h"
#include "string-util.h"

static int fallback_ioctl(sd_device *d, int fd) {
        assert(d);
        assert(fd >= 0);

        if (ioctl(fd, BLKRRPART, 0) < 0)
                return log_device_debug_errno(d, errno, "Failed to reread partition table via BLKRRPART: %m");

        log_device_debug(d, "Successfully reread partition table via BLKRRPART.");
        return 0;
}

#if HAVE_BLKID
static int process_partition(
                sd_device *d,
                int fd,
                blkid_partition pp,
                sd_device_enumerator *e,
                Set **partnos,
                RereadPartitionTableFlags flags,
                bool *changed) {
        int r;

        assert(d);
        assert(fd >= 0);
        assert(pp);
        assert(e);
        assert(partnos);
        assert(changed);

        const char *node;
        r = sd_device_get_devname(d, &node);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to acquire device node path: %m");

        errno = 0;
        int nr = sym_blkid_partition_get_partno(pp);
        if (nr < 0)
                return log_debug_errno(errno_or_else(EIO), "Failed to read partition number of partition: %m");

        log_device_debug(d, "Processing partition %i...", nr);

        errno = 0;
        blkid_loff_t start = sym_blkid_partition_get_start(pp);
        if (start < 0)
                return log_debug_errno(errno_or_else(EIO), "Failed to read partition start offset of partition %i: %m", nr);
        assert((uint64_t) start < UINT64_MAX / 512U);

        errno = 0;
        blkid_loff_t size = sym_blkid_partition_get_size(pp);
        if (size < 0)
                return log_debug_errno(errno_or_else(EIO), "Failed to read partition size of partition %i: %m", nr);
        assert((uint64_t) size < UINT64_MAX / 512U);

        for (sd_device *partition = sd_device_enumerator_get_device_first(e);
             partition;
             partition = sd_device_enumerator_get_device_next(e)) {

                unsigned nr_kernel;
                r = device_get_property_uint(partition, "PARTN", &nr_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to read partition number property: %m");
                if ((unsigned) nr != nr_kernel)
                        continue;

                if (set_ensure_put(partnos, /* hash_ops= */ NULL, UINT_TO_PTR(nr_kernel)) < 0)
                        return log_oom_debug();

                const char *devname;
                r = sd_device_get_devname(partition, &devname);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get name of partition: %m");

                uint64_t start_kernel;
                r = device_get_sysattr_u64(partition, "start", &start_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get start of kernel partition '%s': %m", devname);

                uint64_t size_kernel;
                r = device_get_sysattr_u64(partition, "size", &size_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get size of kernel partition '%s': %m", devname);

                if (start_kernel == (uint64_t) start && size_kernel == (uint64_t) size) {
                        log_device_debug(partition, "Kernel partition '%s' already matches partition table, not modifying.", devname);

                        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                                if (!*changed) {
                                        /* Make sure to synthesize a change even on the main device, before we issue the first one on a partition device */
                                        r = sd_device_trigger(d, SD_DEVICE_CHANGE);
                                        if (r < 0)
                                                return log_device_debug_errno(d, r, "Failed to issue 'change' uevent on device '%s': %m", node);

                                        log_device_debug(partition, "Successfully issued 'change' uevent on device '%s'.", node);
                                        *changed = true;
                                }

                                r = sd_device_trigger(partition, SD_DEVICE_CHANGE);
                                if (r < 0)
                                        return log_device_debug_errno(partition, r, "Failed to issue 'change' uevent on partition '%s': %m", devname);

                                log_device_debug(partition, "Successfully issued 'change' uevent on partition '%s'.", devname);
                        }

                        return 0;
                }

                if (start_kernel != (uint64_t) start) {
                        /* If the start offset changed we need to remove and recreate the partition */
                        log_device_debug(partition, "Removing and recreating partition %i...", nr);

                        r = block_device_remove_partition(fd, devname, (int) nr);
                        if (r < 0)
                                return log_device_debug_errno(partition, r, "Failed to remove kernel partition '%s' in order to recreate it: %m", devname);

                        /* And now add it */
                        log_device_debug(partition, "Successfully removed kernel partition '%s' in order to recreate it.", devname);
                        break;
                }

                /* If the start offsize doesn't change we can just resize the partition */
                log_device_debug(partition, "Resizing partition %i...", nr);

                r = block_device_resize_partition(fd, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to resize kernel partition '%s' to partition table values: %m", devname);

                log_device_debug(partition, "Successfully resized kernel partition '%s' to match partition table.", devname);
                *changed = true;
                return 1;
        }

        log_device_debug(d, "Adding partition %i...", nr);

        _cleanup_free_ char *subnode = NULL;
        r = partition_node_of(node, nr, &subnode);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to determine partition device: %m");

        r = block_device_add_partition(fd, subnode, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to add kernel partition '%i' to partition table values: %m", nr);

        log_device_debug(d, "Successfully added kernel partition '%i' to match partition table.", nr);
        *changed = true;
        return 1;
}

static int remove_partitions(sd_device *d, int fd, sd_device_enumerator *e, Set *partnos, bool *changed) {
        int r;

        assert(d);
        assert(fd >= 0);
        assert(e);
        assert(changed);

        /* Removes all partitions of the specified device that we didn't find in the partition table (as
         * listed in the specified Set object) */

        int ret = 0;
        for (sd_device *partition = sd_device_enumerator_get_device_first(e);
             partition;
             partition = sd_device_enumerator_get_device_next(e)) {
                const char *devname;

                r = sd_device_get_devname(partition, &devname);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get name of partition: %m");

                unsigned nr;
                r = device_get_property_uint(partition, "PARTN", &nr);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to read partition number property: %m");
                if (set_contains(partnos, UINT_TO_PTR(nr))) {
                        log_device_debug(partition, "Found kernel partition %u in partition table, leaving around.", nr);
                        continue;
                }

                log_device_debug(d, "Kernel knows partition %u which we didn't find, removing.", nr);

                r = block_device_remove_partition(fd, devname, (int) nr);
                if (r < 0)
                        RET_GATHER(ret, log_device_debug_errno(d, r, "Failed to remove kernel partition '%s' that vanished from partition table: %m", devname));
                else  {
                        log_device_debug(d, "Removed partition %u from kernel.", nr);
                        *changed = true;
                }
        }

        return ret;
}
#endif

static int rereadpt_full(sd_device *dev, int fd, RereadPartitionTableFlags flags) {
        int r;

        assert(dev);
        assert(fd >= 0);

        const char *p;
        r = sd_device_get_devname(dev, &p);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get block device name: %m");

        r = blockdev_partscan_enabled(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to test if block device '%s' knows partition scanning: %m", p);
        if (r == 0)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENOTTY), "Block device '%s' does not support partition scanning.", p);

#if HAVE_BLKID
        r = dlopen_libblkid();
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to load libblkid: %m");

        _cleanup_close_ int lock_fd = -EBADF;
        if (FLAGS_SET(flags, REREADPT_BSD_LOCK)) {
                lock_fd = fd_reopen(fd, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (lock_fd < 0)
                        return log_device_debug_errno(dev, r, "Failed top open lock fd for block device '%s': %m", p);

                if (flock(lock_fd, LOCK_EX|LOCK_NB) < 0)
                        return log_device_debug_errno(dev, errno, "Failed to take BSD lock on block device '%s': %m", p);
        }

        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        b = sym_blkid_new_probe();
        if (!b)
                return log_oom_debug();

        errno = 0;
        r = sym_blkid_probe_set_device(b, fd, /* off= */ 0, /* size= */ 0);
        if (r != 0)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to open block device '%s': %m", p);

        (void) sym_blkid_probe_enable_partitions(b, 1);
        (void) sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to probe for partition table of '%s': %m", p);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND)) {
                log_device_debug(dev, "Didn't find partition table on block device '%s', falling back to BLKRRPART.", p);
                return fallback_ioctl(dev, fd);
        }

        assert(r == _BLKID_SAFEPROBE_FOUND);

        const char *pttype = NULL;
        (void) sym_blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_device_debug(dev, "Didn't find a GPT partition table on '%s', falling back to BLKRRPART.", p);
                return fallback_ioctl(dev, fd);
        }

        blkid_partlist pl;
        errno = 0;
        pl = sym_blkid_probe_get_partitions(b);
        if (!pl)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to read partition table of '%s': %m", p);

        int n_partitions;
        errno = 0;
        n_partitions = sym_blkid_partlist_numof_partitions(pl);
        if (n_partitions < 0)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to acquire number of entries in partition table of '%s': %m", p);

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to enumerate kernel partitions: %m");

        log_device_debug(dev, "Updating/adding kernel partitions...");

        _cleanup_(set_freep) Set *found_partnos = NULL;
        bool changed = false;
        int ret = 0;
        for (int i = 0; i < n_partitions; i++) {
                blkid_partition pp;
                errno = 0;
                pp = sym_blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to get partition data of partition %i of partition table of '%s': %m", i, p);

                RET_GATHER(ret, process_partition(dev, fd, pp, e, &found_partnos, flags, &changed));
        }

        /* Only delete unrecognized partitions if everything else worked */
        if (ret < 0)
                return ret;

        log_device_debug(dev, "Removing old kernel partitions...");

        r = remove_partitions(dev, fd, e, found_partnos, &changed);
        if (r < 0)
                return r;

        if (changed)
                return 1;

        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                /* No change? Then trigger an event manually if we were told to */
                r = sd_device_trigger(dev, SD_DEVICE_CHANGE);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to issue 'change' uevent on device '%s': %m", p);
        }

        return 0;
#else
        log_device_debug(dev, "We don't have libblkid, falling back to BLKRRPART on '%s'.", p);
        return fallback_ioctl(dev, fd);
#endif
}

int rereadpt(sd_device *dev, RereadPartitionTableFlags flags) {
        assert(dev);

        _cleanup_close_ int fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open block device: %m");

        return rereadpt_full(dev, fd, flags);
}

int rereadpt_fd(int fd, RereadPartitionTableFlags flags) {
        int r;

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = block_device_new_from_fd(fd, /* flags= */ 0, &dev);
        if (r < 0)
                return log_debug_errno(r, "Failed to get block device object: %m");

        return rereadpt_full(dev, fd, flags);
}
