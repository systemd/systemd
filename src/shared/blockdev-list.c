/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "ansi-color.h"
#include "blockdev-list.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "macro.h"
#include "terminal-util.h"

int blockdev_list(BlockDevListFlags flags) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

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

                if (FLAGS_SET(flags, BLOCKDEV_LIST_IGNORE_ZRAM)) {
                        const char *dn;

                        r = sd_device_get_sysname(dev, &dn);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to get device name of discovered block device '%s', ignoring: %m", node);
                                continue;
                        }

                        if (startswith(dn, "zram"))
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

                printf("%s\n", node);

                if (FLAGS_SET(flags, BLOCKDEV_LIST_SHOW_SYMLINKS)) {
                        _cleanup_strv_free_ char **list = NULL;

                        FOREACH_DEVICE_DEVLINK(dev, l)
                                if (strv_extend(&list, l) < 0)
                                        return log_oom();

                        strv_sort(list);

                        STRV_FOREACH(i, list)
                                printf("%s%s%s%s\n", on_tty() ? "    " : "", ansi_grey(), *i, ansi_normal());
                }
        }

        return 0;
}
