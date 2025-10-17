/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "blockdev-list.h"
#include "blockdev-util.h"
#include "device-private.h"
#include "device-util.h"
#include "strv.h"
#include "terminal-util.h"

void block_device_done(BlockDevice *d) {
        assert(d);

        d->node = mfree(d->node);
        d->symlinks = strv_free(d->symlinks);
 }

void block_device_array_free(BlockDevice *d, size_t n_devices) {

        FOREACH_ARRAY(i, d, n_devices)
                block_device_done(d);

        free(d);
}

int blockdev_list(BlockDevListFlags flags, BlockDevice **ret_devices, size_t *ret_n_devices) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(!!ret_devices == !!ret_n_devices);

        /* If ret_devices/ret_n_devices are passed, returns a list of matching block devices, otherwise
         * prints the list to stdout */

        BlockDevice *l = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(l, n, block_device_array_free);

        dev_t root_devno = 0;
        if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_ROOT))
                if (blockdev_get_root(LOG_DEBUG, &root_devno) > 0) {
                        r = block_get_whole_disk(root_devno, &root_devno);
                        if (r < 0)
                                log_debug_errno(r, "Failed to get whole block device of root device: %m");
                }

        if (sd_device_enumerator_new(&e) < 0)
                return log_oom();

        r = sd_device_enumerator_add_match_subsystem(e, "block", /* match = */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to add subsystem match: %m");

        if (FLAGS_SET(flags, BLOCKDEV_LIST_REQUIRE_LUKS)) {
                r = sd_device_enumerator_add_match_property(e, "ID_FS_TYPE", "crypto_LUKS");
                if (r < 0)
                        return log_error_errno(r, "Failed to add match for LUKS block devices: %m");
        }

        FOREACH_DEVICE(e, dev) {
                const char *node;

                r = sd_device_get_devname(dev, &node);
                if (r < 0) {
                        log_warning_errno(r, "Failed to get device node of discovered block device, ignoring: %m");
                        continue;
                }

                if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_ROOT) && root_devno != 0) {
                        dev_t devno;

                        r = sd_device_get_devnum(dev, &devno);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to get major/minor of discovered block device, ignoring: %m");
                                continue;
                        }

                        if (devno == root_devno)
                                continue;
                }

                if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_ZRAM)) {
                        r = device_sysname_startswith(dev, "zram");
                        if (r < 0) {
                                log_warning_errno(r, "Failed to check device name of discovered block device '%s', ignoring: %m", node);
                                continue;
                        }
                        if (r > 0)
                                continue;
                }

                if (FLAGS_SET(flags, BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING)) {
                        r = blockdev_partscan_enabled(dev);
                        if (r < 0) {
                                log_warning_errno(r, "Unable to determine whether '%s' supports partition scanning, skipping device: %m", node);
                                continue;
                        }
                        if (r == 0) {
                                log_debug("Device '%s' does not support partition scanning, skipping.", node);
                                continue;
                        }
                }

                uint64_t size = UINT64_MAX;
                if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_EMPTY) || ret_devices) {

                        r = device_get_sysattr_u64(dev, "size", &size);
                        if (r < 0)
                                log_debug_errno(r, "Failed to acquire size of device '%s', ignoring: %m", node);
                        else
                                /* the 'size' sysattr is always in multiples of 512, even on 4K sector block devices! */
                                assert_se(MUL_ASSIGN_SAFE(&size, 512)); /* Overflow check for coverity */

                        if (size == 0 && FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_EMPTY)) {
                                log_debug("Device '%s' has a zero size, assuming drive without a medium, skipping.", node);
                                continue;
                        }
                }

                _cleanup_strv_free_ char **list = NULL;
                if (FLAGS_SET(flags, BLOCKDEV_LIST_SHOW_SYMLINKS)) {
                        FOREACH_DEVICE_DEVLINK(dev, sl)
                                if (strv_extend(&list, sl) < 0)
                                        return log_oom();

                        strv_sort(list);
                }

                if (ret_devices) {
                        uint64_t diskseq = UINT64_MAX;
                        r = sd_device_get_diskseq(dev, &diskseq);
                        if (r < 0)
                                log_debug_errno(r, "Failed to acquire diskseq of device '%s', ignoring: %m", node);

                        if (!GREEDY_REALLOC(l, n+1))
                                return log_oom();

                        _cleanup_free_ char *m = strdup(node);
                        if (!m)
                                return log_oom();

                        l[n++] = (BlockDevice) {
                                .node = TAKE_PTR(m),
                                .symlinks = TAKE_PTR(list),
                                .diskseq = diskseq,
                                .size = size,
                        };

                } else {
                        printf("%s\n", node);

                        if (FLAGS_SET(flags, BLOCKDEV_LIST_SHOW_SYMLINKS))
                                STRV_FOREACH(i, list)
                                        printf("%s%s%s%s\n", on_tty() ? "    " : "", ansi_grey(), *i, ansi_normal());
                }
        }

        if (ret_devices)
                *ret_devices = TAKE_PTR(l);
        if (ret_n_devices)
                *ret_n_devices = n;

        return 0;
}
