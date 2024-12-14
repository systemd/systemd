/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * probe disks for filesystems and partitions
 *
 * Copyright © 2011 Karel Zak <kzak@redhat.com>
 */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "fd-util.h"
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
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID_ENC", s);

        } else if (streq(name, "UUID_SUB")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID_SUB", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_UUID_SUB_ENC", s);

        } else if (streq(name, "LABEL")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_LABEL", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_LABEL_ENC", s);

        } else if (STR_IN_SET(name, "FSSIZE", "FSLASTBLOCK", "FSBLOCKSIZE")) {
                strscpyl(s, sizeof(s), "ID_FS_", name + 2, NULL);
                udev_builtin_add_property(event, s, value);

        } else if (streq(name, "PTTYPE")) {
                udev_builtin_add_property(event, "ID_PART_TABLE_TYPE", value);

        } else if (streq(name, "PTUUID")) {
                udev_builtin_add_property(event, "ID_PART_TABLE_UUID", value);

        } else if (streq(name, "PART_ENTRY_NAME")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_PART_ENTRY_NAME", s);

        } else if (streq(name, "PART_ENTRY_TYPE")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_PART_ENTRY_TYPE", s);

        } else if (startswith(name, "PART_ENTRY_")) {
                strscpyl(s, sizeof(s), "ID_", name, NULL);
                udev_builtin_add_property(event, s, value);

        } else if (streq(name, "SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_SYSTEM_ID", s);

        } else if (streq(name, "PUBLISHER_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_PUBLISHER_ID", s);

        } else if (streq(name, "APPLICATION_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_APPLICATION_ID", s);

        } else if (streq(name, "BOOT_SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_BOOT_SYSTEM_ID", s);

        } else if (streq(name, "VOLUME_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_VOLUME_ID", s);

        } else if (streq(name, "LOGICAL_VOLUME_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_LOGICAL_VOLUME_ID", s);

        } else if (streq(name, "VOLUME_SET_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_VOLUME_SET_ID", s);

        } else if (streq(name, "DATA_PREPARER_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(event, "ID_FS_DATA_PREPARER_ID", s);
        }
}

static int find_gpt_root(UdevEvent *event, blkid_probe pr) {

#if defined(SD_GPT_ROOT_NATIVE) && ENABLE_EFI

        _cleanup_free_ char *root_label = NULL;
        bool found_esp_or_xbootldr = false;
        sd_id128_t root_id = SD_ID128_NULL;
        int r;

        assert(event);
        assert(pr);

        /* Iterate through the partitions on this disk, and see if the UEFI ESP or XBOOTLDR partition we
         * booted from is on it. If so, find the first root disk, and add a property indicating its partition
         * UUID. */

        errno = 0;
        blkid_partlist pl = blkid_probe_get_partitions(pr);
        if (!pl)
                return errno_or_else(ENOMEM);

        int nvals = blkid_partlist_numof_partitions(pl);
        for (int i = 0; i < nvals; i++) {
                blkid_partition pp;
                const char *label;
                sd_id128_t type, id;

                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        continue;

                r = blkid_partition_get_uuid_id128(pp, &id);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get partition UUID, ignoring: %m");
                        continue;
                }

                r = blkid_partition_get_type_id128(pp, &type);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get partition type UUID, ignoring: %m");
                        continue;
                }

                label = blkid_partition_get_name(pp); /* returns NULL if empty */

                if (sd_id128_in_set(type, SD_GPT_ESP, SD_GPT_XBOOTLDR)) {
                        sd_id128_t esp_or_xbootldr;

                        /* We found an ESP or XBOOTLDR, let's see if it matches the ESP/XBOOTLDR we booted from. */

                        r = efi_loader_get_device_part_uuid(&esp_or_xbootldr);
                        if (r < 0)
                                return r;

                        if (sd_id128_equal(id, esp_or_xbootldr))
                                found_esp_or_xbootldr = true;

                } else if (sd_id128_equal(type, SD_GPT_ROOT_NATIVE)) {
                        unsigned long long flags;

                        flags = blkid_partition_get_flags(pp);
                        if (flags & SD_GPT_FLAG_NO_AUTO)
                                continue;

                        /* We found a suitable root partition, let's remember the first one, or the one with
                         * the newest version, as determined by comparing the partition labels. */

                        if (sd_id128_is_null(root_id) || strverscmp_improved(label, root_label) > 0) {
                                root_id = id;

                                r = free_and_strdup(&root_label, label);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        /* We found the ESP/XBOOTLDR on this disk, and also found a root partition, nice! Let's export its
         * UUID */
        if (found_esp_or_xbootldr && !sd_id128_is_null(root_id))
                udev_builtin_add_property(event, "ID_PART_GPT_AUTO_ROOT_UUID", SD_ID128_TO_UUID_STRING(root_id));
#endif

        return 0;
}

static int probe_superblocks(blkid_probe pr) {
        struct stat st;
        int rc;

        /* TODO: Return negative errno. */

        if (fstat(blkid_probe_get_fd(pr), &st))
                return -errno;

        blkid_probe_enable_partitions(pr, 1);

        if (!S_ISCHR(st.st_mode) &&
            blkid_probe_get_size(pr) <= 1024 * 1440 &&
            blkid_probe_is_wholedisk(pr)) {
                /*
                 * check if the small disk is partitioned, if yes then
                 * don't probe for filesystems.
                 */
                blkid_probe_enable_superblocks(pr, 0);

                rc = blkid_do_fullprobe(pr);
                if (rc < 0)
                        return rc;        /* -1 = error, 1 = nothing, 0 = success */

                if (blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0)
                        return 0;        /* partition table detected */
        }

        blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);
        blkid_probe_enable_superblocks(pr, 1);

        return blkid_do_safeprobe(pr);
}

static int read_loopback_backing_inode(
                sd_device *dev,
                int fd,
                dev_t *ret_devno,
                ino_t *ret_inode,
                char **ret_fname) {

        _cleanup_free_ char *fn = NULL;
        struct loop_info64 info;
        const char *name;
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

        r = sd_device_get_sysname(dev, &name);
        if (r < 0)
                return r;

        if (!startswith(name, "loop"))
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

        errno = 0;
        pr = blkid_new_probe();
        if (!pr)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to create blkid prober: %m");

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "o:H:R", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'H':
#if HAVE_BLKID_PROBE_SET_HINT
                        errno = 0;
                        r = blkid_probe_set_hint(pr, optarg, 0);
                        if (r < 0)
                                return log_device_error_errno(dev, errno_or_else(ENOMEM), "Failed to use '%s' probing hint: %m", optarg);
                        break;
#else
                        /* Use the hint <name>=<offset> as probing offset for old versions */
                        optarg = strchr(optarg, '=');
                        if (!optarg)
                                /* no value means 0, do nothing for old versions */
                                break;
                        ++optarg;
                        _fallthrough_;
#endif
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

        blkid_probe_set_superblocks_flags(pr,
                BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID |
                BLKID_SUBLKS_TYPE | BLKID_SUBLKS_SECTYPE |
#ifdef BLKID_SUBLKS_FSINFO
                BLKID_SUBLKS_FSINFO |
#endif
                BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

        if (noraid)
                blkid_probe_filter_superblocks_usage(pr, BLKID_FLTR_NOTIN, BLKID_USAGE_RAID);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device name: %m");

        fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT(fd);
                log_device_debug_errno(dev, fd, "Failed to open block device %s%s: %m",
                                       devnode, ignore ? ", ignoring" : "");
                return ignore ? 0 : fd;
        }

        errno = 0;
        r = blkid_probe_set_device(pr, fd, offset, 0);
        if (r < 0)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to set device to blkid prober: %m");

        log_device_debug(dev, "Probe %s with %sraid and offset=%"PRIi64, devnode, noraid ? "no" : "", offset);

        r = probe_superblocks(pr);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to probe superblocks: %m");

        /* If the device is a partition then its parent passed the root partition UUID to the device */
        (void) sd_device_get_property_value(dev, "ID_PART_GPT_AUTO_ROOT_UUID", &root_partition);

        errno = 0;
        int nvals = blkid_probe_numof_values(pr);
        if (nvals < 0)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to get number of probed values: %m");

        for (int i = 0; i < nvals; i++) {
                if (blkid_probe_get_value(pr, i, &name, &data, NULL) < 0)
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

        if (is_gpt)
                find_gpt_root(event, pr);

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
                        blkid_encode_string(backing_fname, encoded, ELEMENTSOF(encoded));

                        udev_builtin_add_property(event, "ID_LOOP_BACKING_FILENAME", backing_fname);
                        udev_builtin_add_property(event, "ID_LOOP_BACKING_FILENAME_ENC", encoded);
                }
        }

        return 0;
}

const UdevBuiltin udev_builtin_blkid = {
        .name = "blkid",
        .cmd = builtin_blkid,
        .help = "Filesystem and partition probing",
        .run_once = true,
};
