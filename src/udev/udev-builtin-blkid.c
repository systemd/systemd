/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * probe disks for filesystems and partitions
 *
 * Copyright © 2011 Karel Zak <kzak@redhat.com>
 */

#include <blkid.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "device-util.h"
#include "efivars.h"
#include "errno-util.h"
#include "fd-util.h"
#include "gpt.h"
#include "parse-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-builtin.h"

static void print_property(sd_device *dev, bool test, const char *name, const char *value) {
        char s[256];

        s[0] = '\0';

        if (streq(name, "TYPE")) {
                udev_builtin_add_property(dev, test, "ID_FS_TYPE", value);

        } else if (streq(name, "USAGE")) {
                udev_builtin_add_property(dev, test, "ID_FS_USAGE", value);

        } else if (streq(name, "VERSION")) {
                udev_builtin_add_property(dev, test, "ID_FS_VERSION", value);

        } else if (streq(name, "UUID")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID_ENC", s);

        } else if (streq(name, "UUID_SUB")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID_SUB", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID_SUB_ENC", s);

        } else if (streq(name, "LABEL")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_LABEL", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_LABEL_ENC", s);

        } else if (streq(name, "PTTYPE")) {
                udev_builtin_add_property(dev, test, "ID_PART_TABLE_TYPE", value);

        } else if (streq(name, "PTUUID")) {
                udev_builtin_add_property(dev, test, "ID_PART_TABLE_UUID", value);

        } else if (streq(name, "PART_ENTRY_NAME")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_PART_ENTRY_NAME", s);

        } else if (streq(name, "PART_ENTRY_TYPE")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_PART_ENTRY_TYPE", s);

        } else if (startswith(name, "PART_ENTRY_")) {
                strscpyl(s, sizeof(s), "ID_", name, NULL);
                udev_builtin_add_property(dev, test, s, value);

        } else if (streq(name, "SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_SYSTEM_ID", s);

        } else if (streq(name, "PUBLISHER_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_PUBLISHER_ID", s);

        } else if (streq(name, "APPLICATION_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_APPLICATION_ID", s);

        } else if (streq(name, "BOOT_SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_BOOT_SYSTEM_ID", s);
        }
}

static int find_gpt_root(sd_device *dev, blkid_probe pr, bool test) {

#if defined(GPT_ROOT_NATIVE) && ENABLE_EFI

        _cleanup_free_ char *root_id = NULL;
        bool found_esp = false;
        blkid_partlist pl;
        int i, nvals, r;

        assert(pr);

        /* Iterate through the partitions on this disk, and see if the
         * EFI ESP we booted from is on it. If so, find the first root
         * disk, and add a property indicating its partition UUID. */

        errno = 0;
        pl = blkid_probe_get_partitions(pr);
        if (!pl)
                return errno_or_else(ENOMEM);

        nvals = blkid_partlist_numof_partitions(pl);
        for (i = 0; i < nvals; i++) {
                blkid_partition pp;
                const char *stype, *sid;
                sd_id128_t type;

                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        continue;

                sid = blkid_partition_get_uuid(pp);
                if (!sid)
                        continue;

                stype = blkid_partition_get_type_string(pp);
                if (!stype)
                        continue;

                if (sd_id128_from_string(stype, &type) < 0)
                        continue;

                if (sd_id128_equal(type, GPT_ESP)) {
                        sd_id128_t id, esp;

                        /* We found an ESP, let's see if it matches
                         * the ESP we booted from. */

                        if (sd_id128_from_string(sid, &id) < 0)
                                continue;

                        r = efi_loader_get_device_part_uuid(&esp);
                        if (r < 0)
                                return r;

                        if (sd_id128_equal(id, esp))
                                found_esp = true;

                } else if (sd_id128_equal(type, GPT_ROOT_NATIVE)) {
                        unsigned long long flags;

                        flags = blkid_partition_get_flags(pp);
                        if (flags & GPT_FLAG_NO_AUTO)
                                continue;

                        /* We found a suitable root partition, let's
                         * remember the first one. */

                        if (!root_id) {
                                root_id = strdup(sid);
                                if (!root_id)
                                        return -ENOMEM;
                        }
                }
        }

        /* We found the ESP on this disk, and also found a root
         * partition, nice! Let's export its UUID */
        if (found_esp && root_id)
                udev_builtin_add_property(dev, test, "ID_PART_GPT_AUTO_ROOT_UUID", root_id);
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

static int builtin_blkid(sd_device *dev, int argc, char *argv[], bool test) {
        const char *devnode, *root_partition = NULL, *data, *name;
        _cleanup_(blkid_free_probep) blkid_probe pr = NULL;
        bool noraid = false, is_gpt = false;
        _cleanup_close_ int fd = -1;
        int64_t offset = 0;
        int nvals, i, r;

        static const struct option options[] = {
                { "offset", required_argument, NULL, 'o' },
                { "noraid", no_argument, NULL, 'R' },
                {}
        };

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "o:R", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'o':
                        r = safe_atoi64(optarg, &offset);
                        if (r < 0)
                                return log_device_error_errno(dev, r, "Failed to parse '%s' as an integer: %m", optarg);
                        if (offset < 0)
                                return log_device_error_errno(dev, SYNTHETIC_ERRNO(ERANGE), "Invalid offset %"PRIi64": %m", offset);
                        break;
                case 'R':
                        noraid = true;
                        break;
                }
        }

        errno = 0;
        pr = blkid_new_probe();
        if (!pr)
                return log_device_debug_errno(dev, errno > 0 ? errno : ENOMEM, "Failed to create blkid prober: %m");

        blkid_probe_set_superblocks_flags(pr,
                BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID |
                BLKID_SUBLKS_TYPE | BLKID_SUBLKS_SECTYPE |
                BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

        if (noraid)
                blkid_probe_filter_superblocks_usage(pr, BLKID_FLTR_NOTIN, BLKID_USAGE_RAID);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device name: %m");

        fd = open(devnode, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_device_debug_errno(dev, errno, "Failed to open block device %s: %m", devnode);

        errno = 0;
        r = blkid_probe_set_device(pr, fd, offset, 0);
        if (r < 0)
                return log_device_debug_errno(dev, errno > 0 ? errno : ENOMEM, "Failed to set device to blkid prober: %m");

        log_device_debug(dev, "Probe %s with %sraid and offset=%"PRIi64, devnode, noraid ? "no" : "", offset);

        r = probe_superblocks(pr);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to probe superblocks: %m");

        /* If the device is a partition then its parent passed the root partition UUID to the device */
        (void) sd_device_get_property_value(dev, "ID_PART_GPT_AUTO_ROOT_UUID", &root_partition);

        errno = 0;
        nvals = blkid_probe_numof_values(pr);
        if (nvals < 0)
                return log_device_debug_errno(dev, errno > 0 ? errno : ENOMEM, "Failed to get number of probed values: %m");

        for (i = 0; i < nvals; i++) {
                if (blkid_probe_get_value(pr, i, &name, &data, NULL) < 0)
                        continue;

                print_property(dev, test, name, data);

                /* Is this a disk with GPT partition table? */
                if (streq(name, "PTTYPE") && streq(data, "gpt"))
                        is_gpt = true;

                /* Is this a partition that matches the root partition
                 * property inherited from the parent? */
                if (root_partition && streq(name, "PART_ENTRY_UUID") && streq(data, root_partition))
                        udev_builtin_add_property(dev, test, "ID_PART_GPT_AUTO_ROOT", "1");
        }

        if (is_gpt)
                find_gpt_root(dev, pr, test);

        return 0;
}

const UdevBuiltin udev_builtin_blkid = {
        .name = "blkid",
        .cmd = builtin_blkid,
        .help = "Filesystem and partition probing",
        .run_once = true,
};
