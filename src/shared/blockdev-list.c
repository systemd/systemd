/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "blockdev-list.h"
#include "blockdev-util.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

void block_device_done(BlockDevice *d) {
        assert(d);

        d->node = mfree(d->node);
        d->symlinks = strv_free(d->symlinks);
        d->model = mfree(d->model);
        d->vendor = mfree(d->vendor);
        d->subsystem = mfree(d->subsystem);
 }

void block_device_array_free(BlockDevice *d, size_t n_devices) {

        FOREACH_ARRAY(i, d, n_devices)
                block_device_done(d);

        free(d);
}

static int blockdev_get_prop(sd_device *d, const char *prop1, const char *prop2, char **ret_value) {
        int r, ret = 0;

        assert(d);
        assert(prop1);
        assert(ret_value);

        FOREACH_STRING(prop, prop1, prop2) {
                const char *m = NULL;
                r = sd_device_get_property_value(d, prop, &m);
                if (r < 0 && r != -ENOENT)
                        RET_GATHER(ret, log_device_debug_errno(d, r, "Failed to acquire '%s' from device, ignoring: %m", prop));
                else if (!isempty(m))
                        return strdup_to(ret_value, m);
        }

        return ret < 0 ? ret : -ENOENT;
}

static int blockdev_get_subsystem(sd_device *d, char **ret_subsystem) {
        int r;

        assert(d);
        assert(ret_subsystem);

        /* We prefer the explicitly set block device subsystem property, because if it is set it's generally
         * the most useful. If it's not set we'll look for the subsystem of the first parent device that
         * isn't of subsystem 'block'. The former covers 'virtual' block devices such as loopback, device
         * mapper, zram, while the latter covers physical block devices such as USB or NVME. */

        r = blockdev_get_prop(d, "ID_BLOCK_SUBSYSTEM", /* prop2= */ NULL, ret_subsystem);
        if (r >= 0)
                return r;

        int ret = r != -ENOENT ? r : 0;
        sd_device *q = d;
        for (;;) {
                r = sd_device_get_parent(q, &q);
                if (r < 0) {
                        if (r != -ENOENT)
                                RET_GATHER(ret, log_device_debug_errno(q, r, "Failed to get parent device, ignoring: %m"));
                        break;
                }

                const char *s = NULL;
                r = sd_device_get_subsystem(q, &s);
                if (r < 0)
                        RET_GATHER(ret, log_device_debug_errno(q, r, "Failed to get subsystem of device, ignoring: %m"));
                else if (!isempty(s) && !streq(s, "block"))
                        return strdup_to(ret_subsystem, s);
        }

        return ret < 0 ? ret : -ENOENT;
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

        r = sd_device_enumerator_add_match_subsystem(e, "block", /* match= */ true);
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
                        log_device_warning_errno(dev, r, "Failed to get device node of discovered block device, ignoring: %m");
                        continue;
                }

                if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_ROOT) && root_devno != 0) {
                        dev_t devno;

                        r = sd_device_get_devnum(dev, &devno);
                        if (r < 0) {
                                log_device_warning_errno(dev, r, "Failed to get major/minor of discovered block device, ignoring: %m");
                                continue;
                        }

                        if (devno == root_devno)
                                continue;
                }

                if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_ZRAM)) {
                        r = device_sysname_startswith(dev, "zram");
                        if (r < 0) {
                                log_device_warning_errno(dev, r, "Failed to check device name of discovered block device '%s', ignoring: %m", node);
                                continue;
                        }
                        if (r > 0)
                                continue;
                }

                if (FLAGS_SET(flags, BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING)) {
                        r = blockdev_partscan_enabled(dev);
                        if (r < 0) {
                                log_device_warning_errno(dev, r, "Unable to determine whether '%s' supports partition scanning, skipping device: %m", node);
                                continue;
                        }
                        if (r == 0) {
                                log_device_debug(dev, "Device '%s' does not support partition scanning, skipping.", node);
                                continue;
                        }
                }

                uint64_t size = UINT64_MAX;
                if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_EMPTY) || ret_devices) {
                        r = device_get_sysattr_u64(dev, "size", &size);
                        if (r < 0)
                                log_device_debug_errno(dev, r, "Failed to acquire size of device '%s', ignoring: %m", node);
                        else
                                /* the 'size' sysattr is always in multiples of 512, even on 4K sector block devices! */
                                assert_se(MUL_ASSIGN_SAFE(&size, 512)); /* Overflow check for coverity */

                        if (size == 0 && FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_EMPTY)) {
                                log_device_debug(dev, "Device '%s' has a zero size, assuming drive without a medium, skipping.", node);
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

                _cleanup_free_ char *model = NULL, *vendor = NULL, *subsystem = NULL;
                if (FLAGS_SET(flags, BLOCKDEV_LIST_METADATA)) {
                        (void) blockdev_get_prop(dev, "ID_MODEL_FROM_DATABASE", "ID_MODEL", &model);
                        (void) blockdev_get_prop(dev, "ID_VENDOR_FROM_DATABASE", "ID_VENDOR", &vendor);
                        (void) blockdev_get_subsystem(dev, &subsystem);
                }

                if (ret_devices) {
                        uint64_t diskseq = UINT64_MAX;
                        r = sd_device_get_diskseq(dev, &diskseq);
                        if (r < 0)
                                log_device_debug_errno(dev, r, "Failed to acquire diskseq of device '%s', ignoring: %m", node);

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
                                .model = TAKE_PTR(model),
                                .vendor = TAKE_PTR(vendor),
                                .subsystem = TAKE_PTR(subsystem),
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
