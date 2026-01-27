/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fs.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "reread-partition-table.h"
#include "set.h"
#include "string-util.h"

static int trigger_partitions(sd_device *dev, bool blkrrpart_success) {
        int ret = 0, r;

        assert(dev);

        /* search for partitions */
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to initialize partition enumerator: %m");

        /* We have partitions and re-read the table, the kernel already sent out a "change"
         * event for the disk, and "remove/add" for all partitions. */
        if (blkrrpart_success && sd_device_enumerator_get_device_first(e))
                return 0;

        /* We have partitions but re-reading the partition table did not work, synthesize
         * "change" for the disk and all partitions. */
        r = sd_device_trigger(dev, SD_DEVICE_CHANGE);
        if (r < 0)
                RET_GATHER(ret, log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent, proceeding: %m"));

        FOREACH_DEVICE(e, d) {
                r = sd_device_trigger(d, SD_DEVICE_CHANGE);
                if (r < 0)
                        RET_GATHER(ret, log_device_debug_errno(d, r, "Failed to trigger 'change' uevent, proceeding: %m"));
        }

        return ret;
}

static int fallback_ioctl(sd_device *d, int fd, RereadPartitionTableFlags flags) {
        int r;

        assert(d);
        assert(fd >= 0);

        r = RET_NERRNO(ioctl(fd, BLKRRPART, 0));
        if (r < 0)
                log_device_debug_errno(d, r, "Failed to reread partition table via BLKRRPART: %m");
        else
                log_device_debug(d, "Successfully reread partition table via BLKRRPART.");

        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT))
                RET_GATHER(r, trigger_partitions(d, r >= 0));

        return r;
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

        if (set_ensure_put(partnos, /* hash_ops= */ NULL, UINT_TO_PTR(nr)) < 0)
                return log_oom_debug();

        _cleanup_free_ char *subnode = NULL;
        r = partition_node_of(node, nr, &subnode);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to determine partition node %i for '%s': %m", nr, node);

        _cleanup_(sd_device_unrefp) sd_device *partition = NULL;
        r = sd_device_new_from_devname(&partition, subnode);
        if (r < 0) {
                if (r != -ENODEV)
                        return log_device_debug_errno(d, r, "Failed to acquire device '%s': %m", subnode);
        } else {
                uint64_t start_kernel;
                r = device_get_sysattr_u64(partition, "start", &start_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get start of kernel partition device '%s': %m", subnode);

                uint64_t size_kernel;
                r = device_get_sysattr_u64(partition, "size", &size_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get size of kernel partition device '%s': %m", subnode);

                if (start_kernel == (uint64_t) start && size_kernel == (uint64_t) size) {
                        log_device_debug(partition, "Kernel partition device '%s' already matches partition table, not modifying.", subnode);

                        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                                if (!*changed) {
                                        /* Make sure to synthesize a change event on the main device, before we issue the first one on a partition device */
                                        r = sd_device_trigger(d, SD_DEVICE_CHANGE);
                                        if (r < 0)
                                                return log_device_debug_errno(d, r, "Failed to issue 'change' uevent on device '%s': %m", node);

                                        log_device_debug(d, "Successfully issued 'change' uevent on device '%s'.", node);
                                        *changed = true;
                                }

                                r = sd_device_trigger(partition, SD_DEVICE_CHANGE);
                                if (r < 0)
                                        return log_device_debug_errno(partition, r, "Failed to issue 'change' uevent on partition '%s': %m", subnode);

                                log_device_debug(partition, "Successfully issued 'change' uevent on partition '%s'.", subnode);
                        }

                        return 0;
                }

                if (start_kernel == (uint64_t) start) {
                        /* If the start offsize doesn't change we can just resize the partition */
                        log_device_debug(partition, "Resizing partition %i...", nr);

                        r = block_device_resize_partition(fd, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
                        if (r < 0)
                                return log_device_debug_errno(partition, r, "Failed to resize kernel partition device '%s' to partition table values: %m", subnode);

                        log_device_debug(partition, "Successfully resized kernel partition device '%s' to match partition table.", subnode);
                        *changed = true;
                        return 1;
                }

                /* If the start offset changed we need to remove and recreate the partition */
                log_device_debug(partition, "Removing and recreating partition %i...", nr);

                /* NB: when logging below we use the parent device now, after all the partition device ceased
                 * existing by now, most likely. Let's explicitly get rid of the obsolete device object now,
                 * just to make a point. */
                partition = sd_device_unref(partition);

                r = block_device_remove_partition(fd, subnode, nr);
                if (r < 0)
                        return log_device_debug_errno(d, r, "Failed to remove kernel partition device '%s' in order to recreate it: %m", subnode);

                /* And now add it the partition anew */
                log_device_debug(d, "Successfully removed kernel partition device '%s' in order to recreate it.", subnode);
        }

        log_device_debug(d, "Adding partition %i...", nr);

        r = block_device_add_partition(fd, subnode, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to add kernel partition device %i to partition table values: %m", nr);

        log_device_debug(d, "Successfully added kernel partition device %i to match partition table.", nr);
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
        FOREACH_DEVICE(e, partition) {
                const char *devname;

                r = sd_device_get_devname(partition, &devname);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get name of partition: %m");

                unsigned nr;
                r = device_get_property_uint(partition, "PARTN", &nr);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to read partition number property: %m");
                if (set_contains(partnos, UINT_TO_PTR(nr))) {
                        log_device_debug(partition, "Found kernel partition device %u in partition table, leaving around.", nr);
                        continue;
                }

                log_device_debug(partition, "Kernel knows partition %u which we didn't find, removing.", nr);

                r = block_device_remove_partition(fd, devname, (int) nr);
                if (r < 0) /* NB: when logging we use the parent device below, after all the partition device ceased existing by now, most likely */
                        RET_GATHER(ret, log_device_debug_errno(d, r, "Failed to remove kernel partition device '%s' that vanished from partition table: %m", devname));
                else  {
                        log_device_debug(d, "Removed partition %u from kernel.", nr);
                        *changed = true;
                }
        }

        return ret;
}
#endif

static int reread_partition_table_full(sd_device *dev, int fd, RereadPartitionTableFlags flags) {
        int r;

        assert(dev);
        assert(fd >= 0);

        const char *p;
        r = sd_device_get_devname(dev, &p);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get block device name: %m");

        _cleanup_close_ int lock_fd = -EBADF;
        if (FLAGS_SET(flags, REREADPT_BSD_LOCK)) {
                lock_fd = fd_reopen(fd, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (lock_fd < 0)
                        return log_device_debug_errno(dev, lock_fd, "Failed to open lock fd for block device '%s': %m", p);

                if (flock(lock_fd, LOCK_EX|LOCK_NB) < 0) {
                        r = log_device_debug_errno(dev, errno, "Failed to take BSD lock on block device '%s': %m", p);

                        if (r == -EAGAIN && FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                                log_device_debug(dev, "Giving up rereading partition table of '%s'. Triggering change events for the device and its partitions.", p);
                                (void) trigger_partitions(dev, /* blkrrpart_success= */ false);
                        }

                        return r;
                }
        }

        r = blockdev_partscan_enabled(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to test if block device '%s' knows partition scanning: %m", p);
        if (r == 0) {
                /* No partition scanning? Generate a uevent at least, if that's requested */
                if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                        r = sd_device_trigger(dev, SD_DEVICE_CHANGE);
                        if (r < 0)
                                return log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent, proceeding: %m");

                        return 0;
                }

                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENOTTY), "Block device '%s' does not support partition scanning.", p);
        }

#if HAVE_BLKID
        r = dlopen_libblkid();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_device_debug(dev, "We don't have libblkid, falling back to BLKRRPART on '%s'.", p);
                return fallback_ioctl(dev, fd, flags);
        }
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to load libblkid: %m");

        _cleanup_(blkid_free_probep) blkid_probe b = sym_blkid_new_probe();
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
                return fallback_ioctl(dev, fd, flags);
        }

        assert(r == _BLKID_SAFEPROBE_FOUND);

        const char *pttype = NULL;
        (void) sym_blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_device_debug(dev, "Didn't find a GPT partition table on '%s', falling back to BLKRRPART.", p);
                return fallback_ioctl(dev, fd, flags);
        }

        errno = 0;
        blkid_partlist pl = sym_blkid_probe_get_partitions(b);
        if (!pl)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to read partition table of '%s': %m", p);

        errno = 0;
        int n_partitions = sym_blkid_partlist_numof_partitions(pl);
        if (n_partitions < 0)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to acquire number of entries in partition table of '%s': %m", p);

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to enumerate kernel partition devices: %m");

        log_device_debug(dev, "Updating/adding kernel partition devices...");

        _cleanup_(set_freep) Set *found_partnos = NULL;
        bool changed = false;
        int ret = 0;
        for (int i = 0; i < n_partitions; i++) {
                errno = 0;
                blkid_partition pp = sym_blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to get partition data of partition %i of partition table of '%s': %m", i, p);

                RET_GATHER(ret, process_partition(dev, fd, pp, e, &found_partnos, flags, &changed));
        }

        /* Only delete unrecognized partitions if everything else worked */
        if (ret < 0)
                return ret;

        log_device_debug(dev, "Removing old kernel partition devices...");

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
        return fallback_ioctl(dev, fd, flags);
#endif
}

int reread_partition_table(sd_device *dev, RereadPartitionTableFlags flags) {
        assert(dev);

        _cleanup_close_ int fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open block device: %m");

        return reread_partition_table_full(dev, fd, flags);
}

int reread_partition_table_fd(int fd, RereadPartitionTableFlags flags) {
        int r;

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = block_device_new_from_fd(fd, /* flags= */ 0, &dev);
        if (r < 0)
                return log_debug_errno(r, "Failed to get block device object: %m");

        return reread_partition_table_full(dev, fd, flags);
}
