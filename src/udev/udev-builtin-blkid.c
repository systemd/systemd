/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * probe disks for filesystems and partitions
 *
 * Copyright © 2011 Karel Zak <kzak@redhat.com>
 */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "fd-util.h"
#include "initrd-util.h"
#include "gpt.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "udev-builtin.h"

static void print_property(UdevEvent *event, const char *name, const char *value) {
        char s[256];

        assert(event);
        assert(name);

        s[0] = '\0';

        if (streq(name, "TYPE")) {
                udev_builtin_add_property(event, "ID_FS_TYPE", value);

        } else if (streq(name, "USAGE")) {
                udev_builtin_add_property(event, "ID_FS_USAGE", value);

        } else if (streq(name, "VERSION")) {
                udev_builtin_add_property(event, "ID_FS_VERSION", value);

        } else if (streq(name, "UUID")) {
                sym_blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID", s);
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID_ENC", s);

        } else if (streq(name, "UUID_SUB")) {
                sym_blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID_SUB", s);
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID_SUB_ENC", s);

        } else if (streq(name, "LABEL")) {
                sym_blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_LABEL", s);
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_LABEL_ENC", s);

        } else if (STR_IN_SET(name, "FSSIZE", "FSLASTBLOCK", "FSBLOCKSIZE")) {
                strscpyl(s, sizeof(s), "ID_FS_", name + 2, NULL);
                udev_builtin_add_property(event, s, value);

        } else if (streq(name, "PTTYPE")) {
                udev_builtin_add_property(event, "ID_PART_TABLE_TYPE", value);

        } else if (streq(name, "PTUUID")) {
                udev_builtin_add_property(event, "ID_PART_TABLE_UUID", value);

        } else if (streq(name, "PART_ENTRY_NAME")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_PART_ENTRY_NAME", s);

        } else if (streq(name, "PART_ENTRY_TYPE")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_PART_ENTRY_TYPE", s);

        } else if (startswith(name, "PART_ENTRY_")) {
                strscpyl(s, sizeof(s), "ID_", name, NULL);
                udev_builtin_add_property(event, s, value);

        } else if (streq(name, "SYSTEM_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_SYSTEM_ID", s);

        } else if (streq(name, "PUBLISHER_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_PUBLISHER_ID", s);

        } else if (streq(name, "APPLICATION_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_APPLICATION_ID", s);

        } else if (streq(name, "BOOT_SYSTEM_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_BOOT_SYSTEM_ID", s);

        } else if (streq(name, "VOLUME_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_VOLUME_ID", s);

        } else if (streq(name, "LOGICAL_VOLUME_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_LOGICAL_VOLUME_ID", s);

        } else if (streq(name, "VOLUME_SET_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_VOLUME_SET_ID", s);

        } else if (streq(name, "DATA_PREPARER_ID")) {
                sym_blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_DATA_PREPARER_ID", s);
        }
}

static int find_gpt_root(UdevEvent *event, blkid_probe pr, const char *loop_backing_fname) {

#if defined(SD_GPT_ROOT_NATIVE) && ENABLE_EFI
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r;

        assert(event);
        assert(pr);

        /* In the initrd: Iterate through the partitions on this disk, and see if the UEFI ESP or XBOOTLDR
         * partition we booted from is on it. If so, find the newest root partition, and add a property
         * indicating its partition UUID. We also do this if we are dealing with a loopback block device
         * whose "backing filename" field is set to the string "root". In the latter case we do not search
         * for ESP or XBOOTLDR.
         *
         * After the initrd→host transition: look at the current block device mounted at / and set the same
         * properties to its whole block device. */

        const char *devnode;
        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device node: %m");

        r = block_device_is_whole_disk(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Unable to determine if device '%s' is a whole-block device: %m", devnode);
        if (r == 0) {
                log_device_debug(dev, "Invoked on device '%s' which is not a whole-disk block device, ignoring.", devnode);
                return 0;
        }

        r = blockdev_partscan_enabled(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to determine if block device '%s' supports partitions: %m", devnode);
        if (r == 0) {
                log_device_debug(dev, "Invoked on block device '%s' that lacks partition scanning, ignoring.", devnode);
                return 0;
        }

        sd_id128_t esp_or_xbootldr = SD_ID128_NULL;
        bool need_esp_or_xbootldr;
        dev_t root_devno = 0;
        if (in_initrd()) {
                /* In the initrd look at the boot loader provided data (and loopback backing fname) to find
                 * our *future* root */

                r = efi_loader_get_device_part_uuid(&esp_or_xbootldr);
                if (r < 0) {
                        if (r != -ENOENT && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                                return log_debug_errno(r, "Unable to determine loader partition UUID: %m");

                        log_device_debug(dev, "No loader partition UUID EFI variable set, not using partition data to search for default root block device.");

                        /* NB: if an ESP/xbootldr field is set, we always use that. We do this in order to guarantee
                         * systematic behaviour. */
                        if (!STRPTR_IN_SET(loop_backing_fname, "rootdisk", "rootdisk.raw")) {
                                log_device_debug(dev, "Device is not a loopback block device with reference string 'root', not considering block device as default root block device.");
                                return 0;
                        }

                        /* OK, we have now sufficiently identified this device as the right root "whole" device,
                         * hence no need to bother with searching for ESP/XBOOTLDR */
                        need_esp_or_xbootldr = false;
                } else
                        /* We now know the the ESP/xbootldr UUID, but we cannot be sure yet it's on this block
                         * device, hence look for it among partitions now */
                        need_esp_or_xbootldr = true;
        } else {
                /* On the main system look at the *current* root instead */

                r = blockdev_get_root(LOG_DEBUG, &root_devno);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Unable to determine current root block device, skipping gpt-auto probing: %m");
                        return 0;
                }
                if (r == 0) {
                        log_device_debug(dev, "Root block device not backed by a (single) whole block device, skipping gpt-auto probing.");
                        return 0;
                }

                dev_t whole_devno;
                r = block_get_whole_disk(root_devno, &whole_devno);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to find whole block device for root block device: %m");

                dev_t this_devno;
                r = sd_device_get_devnum(dev, &this_devno);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to get device major/minor of device: %m");

                if (whole_devno != this_devno) {
                        log_device_debug(dev, "This device is not the current root block device.");
                        return 0;
                }

                /* We don't need to check ESP/XBOOTLDR UUID, we *know* what our root disk is */
                need_esp_or_xbootldr = false;
        }

        errno = 0;
        blkid_partlist pl = sym_blkid_probe_get_partitions(pr);
        if (!pl)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to probe partitions: %m");

        sd_id128_t root_id = SD_ID128_NULL;
        bool found_esp_or_xbootldr = false;

        if (root_devno != 0) {
                /* If we already know the root partition, let's verify its type ID and then directly query
                 * its ID */

                blkid_partition root_partition = sym_blkid_partlist_devno_to_partition(pl, root_devno);
                if (root_partition) {
                        sd_id128_t type;
                        r = blkid_partition_get_type_id128(root_partition, &type);
                        if (r < 0)
                                log_device_debug_errno(dev, r, "Failed to get root partition type UUID, ignoring: %m");
                        else if (sd_id128_equal(type, SD_GPT_ROOT_NATIVE)) {
                                r = blkid_partition_get_uuid_id128(root_partition, &root_id);
                                if (r < 0)
                                        log_device_debug_errno(dev, r, "Failed to get partition UUID, ignoring: %m");
                        }
                }
        } else {
                /* We do not know the root partition, let's search for it. */

                _cleanup_free_ char *root_label = NULL;
                int nvals = sym_blkid_partlist_numof_partitions(pl);
                for (int i = 0; i < nvals; i++) {
                        blkid_partition pp;
                        const char *label;
                        sd_id128_t type, id;

                        pp = sym_blkid_partlist_get_partition(pl, i);
                        if (!pp)
                                continue;

                        r = blkid_partition_get_uuid_id128(pp, &id);
                        if (r < 0) {
                                log_device_debug_errno(dev, r, "Failed to get partition UUID, ignoring: %m");
                                continue;
                        }

                        r = blkid_partition_get_type_id128(pp, &type);
                        if (r < 0) {
                                log_device_debug_errno(dev, r, "Failed to get partition type UUID, ignoring: %m");
                                continue;
                        }

                        label = sym_blkid_partition_get_name(pp); /* returns NULL if empty */

                        if (need_esp_or_xbootldr && sd_id128_in_set(type, SD_GPT_ESP, SD_GPT_XBOOTLDR)) {

                                /* We found an ESP or XBOOTLDR, let's see if it matches the ESP/XBOOTLDR we booted from. */
                                if (sd_id128_equal(id, esp_or_xbootldr))
                                        found_esp_or_xbootldr = true;

                        } else if (sd_id128_equal(type, SD_GPT_ROOT_NATIVE)) {
                                unsigned long long flags;

                                flags = sym_blkid_partition_get_flags(pp);
                                if (flags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                /* systemd-sysupdate expects empty partitions to be marked with an "_empty" label, hence ignore them here. */
                                if (streq_ptr(label, "_empty"))
                                        continue;

                                /* We found a suitable root partition, let's remember the first one, or the one with
                                 * the newest version, as determined by comparing the partition labels. */

                                if (sd_id128_is_null(root_id) || strverscmp_improved(label, root_label) > 0) {
                                        root_id = id;

                                        if (free_and_strdup(&root_label, label) < 0)
                                                return log_oom_debug();
                                }
                        }
                }
        }

        if (!need_esp_or_xbootldr || found_esp_or_xbootldr) {
                /* We found the ESP/XBOOTLDR on this disk (or we didn't need it) */
                udev_builtin_add_property(event, "ID_PART_GPT_AUTO_ROOT_DISK", "1");

                /* We found a root partition, nice! Let's export its UUID. */
                if (!sd_id128_is_null(root_id))
                        udev_builtin_add_property(event, "ID_PART_GPT_AUTO_ROOT_UUID", SD_ID128_TO_UUID_STRING(root_id));
        }
#endif

        return 0;
}

static int probe_superblocks(blkid_probe pr) {
        struct stat st;
        int rc;

        /* TODO: Return negative errno. */

        if (fstat(sym_blkid_probe_get_fd(pr), &st))
                return -errno;

        sym_blkid_probe_enable_partitions(pr, 1);

        if (!S_ISCHR(st.st_mode) &&
            sym_blkid_probe_get_size(pr) <= 1024 * 1440 &&
            sym_blkid_probe_is_wholedisk(pr)) {
                /*
                 * check if the small disk is partitioned, if yes then
                 * don't probe for filesystems.
                 */
                sym_blkid_probe_enable_superblocks(pr, 0);

                rc = sym_blkid_do_fullprobe(pr);
                if (rc < 0)
                        return rc;        /* -1 = error, 1 = nothing, 0 = success */

                if (sym_blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0)
                        return 0;        /* partition table detected */
        }

        sym_blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);
        sym_blkid_probe_enable_superblocks(pr, 1);

        return sym_blkid_do_safeprobe(pr);
}

static int read_loopback_backing_inode(
                sd_device *dev,
                int fd,
                dev_t *ret_devno,
                ino_t *ret_inode,
                char **ret_fname) {

        _cleanup_free_ char *fn = NULL;
        struct loop_info64 info;
        int r;

        assert(dev);
        assert(fd >= 0);
        assert(ret_devno);
        assert(ret_inode);
        assert(ret_fname);

        /* Retrieves various fields of the current loopback device backing file, so that we can ultimately
         * use it to create stable symlinks to loopback block devices, based on what they are backed by. We
         * pick up inode/device as well as file name field. Note that we pick up the "lo_file_name" field
         * here, which is an arbitrary free-form string provided by userspace. We do not return the sysfs
         * attribute loop/backing_file here, because that is directly accessible from udev rules anyway. And
         * sometimes, depending on context, it's a good thing to return the string userspace can freely pick
         * over the string automatically generated by the kernel. */

        r = device_sysname_startswith(dev, "loop");
        if (r < 0)
                return r;
        if (r == 0)
                goto notloop;

        if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        goto notloop;

                return -errno;
        }

#if HAVE_VALGRIND_MEMCHECK_H
        VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

        if (isempty((char*) info.lo_file_name) ||
            strnlen((char*) info.lo_file_name, sizeof(info.lo_file_name)-1) == sizeof(info.lo_file_name)-1)
                /* Don't pick up file name if it is unset or possibly truncated. (Note: the kernel silently
                 * truncates the string passed from userspace by LOOP_SET_STATUS64 ioctl. See
                 * loop_set_status_from_info() in drivers/block/loop.c. Hence, we can't really know the file
                 * name is truncated if it uses sizeof(info.lo_file_name)-1 as length; it could also mean the
                 * string is just that long and wasn't truncated — but the fact is simply that we cannot know
                 * in that case if it was truncated or not. Thus, we assume the worst and suppress — at least
                 * for now. For shorter strings we know for sure it wasn't truncated, hence that's always
                 * safe.) */
                fn = NULL;
        else {
                fn = memdup_suffix0(info.lo_file_name, sizeof(info.lo_file_name));
                if (!fn)
                        return -ENOMEM;
        }

        *ret_inode = info.lo_inode;
        *ret_devno = info.lo_device;
        *ret_fname = TAKE_PTR(fn);
        return 1;

notloop:
        *ret_devno = 0;
        *ret_inode = 0;
        *ret_fname = NULL;
        return 0;
}

static int builtin_blkid(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        const char *devnode, *root_partition = NULL, *data, *name;
        _cleanup_(blkid_free_probep) blkid_probe pr = NULL;
        _cleanup_free_ char *backing_fname = NULL;
        bool noraid = false, is_gpt = false;
        _cleanup_close_ int fd = -EBADF;
        ino_t backing_inode = 0;
        dev_t backing_devno = 0;
        int64_t offset = 0;
        int r;

        static const struct option options[] = {
                { "offset", required_argument, NULL, 'o' },
                { "hint",   required_argument, NULL, 'H' },
                { "noraid", no_argument,       NULL, 'R' },
                {}
        };

        r = dlopen_libblkid();
        if (r < 0)
                return log_device_debug_errno(dev, r, "blkid not available: %m");

        errno = 0;
        pr = sym_blkid_new_probe();
        if (!pr)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to create blkid prober: %m");

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "o:H:R", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'H':
                        errno = 0;
                        r = sym_blkid_probe_set_hint(pr, optarg, 0);
                        if (r < 0)
                                return log_device_error_errno(dev, errno_or_else(ENOMEM), "Failed to use '%s' probing hint: %m", optarg);
                        break;
                case 'o':
                        r = safe_atoi64(optarg, &offset);
                        if (r < 0)
                                return log_device_error_errno(dev, r, "Failed to parse '%s' as an integer: %m", optarg);
                        if (offset < 0)
                                return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invalid offset %"PRIi64".", offset);
                        break;
                case 'R':
                        noraid = true;
                        break;
                }
        }

        sym_blkid_probe_set_superblocks_flags(pr,
                BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID |
                BLKID_SUBLKS_TYPE | BLKID_SUBLKS_SECTYPE |
#ifdef BLKID_SUBLKS_FSINFO /* since util-linux 2.39 */
                BLKID_SUBLKS_FSINFO |
#endif
                BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

        if (noraid)
                sym_blkid_probe_filter_superblocks_usage(pr, BLKID_FLTR_NOTIN, BLKID_USAGE_RAID);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device name: %m");

        fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(fd);
                log_device_debug_errno(dev, fd, "Failed to open block device %s%s: %m",
                                       devnode, ignore ? ", ignoring" : "");
                return ignore ? 0 : fd;
        }

        errno = 0;
        r = sym_blkid_probe_set_device(pr, fd, offset, 0);
        if (r < 0)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to set device to blkid prober: %m");

        log_device_debug(dev, "Probe %s with %sraid and offset=%"PRIi64, devnode, noraid ? "no" : "", offset);

        r = probe_superblocks(pr);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to probe superblocks: %m");

        /* If the device is a partition then its parent passed the root partition UUID to the device */
        (void) sd_device_get_property_value(dev, "ID_PART_GPT_AUTO_ROOT_UUID", &root_partition);

        errno = 0;
        int nvals = sym_blkid_probe_numof_values(pr);
        if (nvals < 0)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to get number of probed values: %m");

        for (int i = 0; i < nvals; i++) {
                if (sym_blkid_probe_get_value(pr, i, &name, &data, NULL) < 0)
                        continue;

                print_property(event, name, data);

                /* Is this a disk with GPT partition table? */
                if (streq(name, "PTTYPE") && streq(data, "gpt"))
                        is_gpt = true;

                /* Is this a partition that matches the root partition
                 * property inherited from the parent? */
                if (root_partition && streq(name, "PART_ENTRY_UUID") && streq(data, root_partition))
                        udev_builtin_add_property(event, "ID_PART_GPT_AUTO_ROOT", "1");
        }

        r = read_loopback_backing_inode(
                        dev,
                        fd,
                        &backing_devno,
                        &backing_inode,
                        &backing_fname);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to read loopback backing inode, ignoring: %m");
        else if (r > 0) {
                udev_builtin_add_propertyf(event, "ID_LOOP_BACKING_DEVICE", DEVNUM_FORMAT_STR, DEVNUM_FORMAT_VAL(backing_devno));
                udev_builtin_add_propertyf(event, "ID_LOOP_BACKING_INODE", "%" PRIu64, (uint64_t) backing_inode);

                if (backing_fname) {
                        /* In the worst case blkid_encode_string() will blow up to 4x the string
                         * length. Hence size the buffer to 4x of the longest string
                         * read_loopback_backing_inode() might return */
                        char encoded[sizeof_field(struct loop_info64, lo_file_name) * 4 + 1];

                        assert(strlen(backing_fname) < ELEMENTSOF(encoded) / 4);
                        sym_blkid_encode_string(backing_fname, encoded, ELEMENTSOF(encoded));

                        udev_builtin_add_property(event, "ID_LOOP_BACKING_FILENAME", backing_fname);
                        udev_builtin_add_property(event, "ID_LOOP_BACKING_FILENAME_ENC", encoded);
                }
        }

        if (is_gpt)
                find_gpt_root(event, pr, backing_fname);

        return 0;
}

const UdevBuiltin udev_builtin_blkid = {
        .name = "blkid",
        .cmd = builtin_blkid,
        .help = "Filesystem and partition probing",
        .run_once = true,
};
