/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/btrfs.h>
#include <sys/ioctl.h>

#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "string-util.h"
#include "udev-builtin.h"

static int builtin_btrfs(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r;

        if (!IN_SET(argc, 2, 3) || !streq(argv[1], "ready"))
                return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invalid arguments.");

        const char *node;
        r = sd_device_get_devname(dev, &node);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get device node: %m");

        if (argc == 3 && !streq(argv[2], node))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Device node '%s' is not owned by the device, it must be '%s'.", argv[2], node);

        if (strlen(node) >= sizeof_field(struct btrfs_ioctl_vol_args, name))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Device name too long for BTRFS_IOC_DEVICES_READY call: %s", node);

        if (event->event_mode != EVENT_UDEV_WORKER) {
                log_device_debug(dev, "Running in test mode, skipping execution of 'btrfs' builtin command.");
                return 0;
        }

        _cleanup_close_ int fd = open("/dev/btrfs-control", O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                if (ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(errno)) {
                        /* Driver not installed? Then we aren't ready. This is useful in initrds that lack
                         * btrfs.ko. After the host transition (where btrfs.ko will hopefully become
                         * available) the device can be retriggered and will then be considered ready. */
                        udev_builtin_add_property(event, "ID_BTRFS_READY", "0");
                        return 0;
                }

                return log_device_debug_errno(dev, errno, "Failed to open %s: %m", "/dev/btrfs-control");
        }

        struct btrfs_ioctl_vol_args args = {};
        strncpy(args.name, node, sizeof(args.name)-1);
        r = ioctl(fd, BTRFS_IOC_DEVICES_READY, &args);
        if (r < 0)
                return log_device_debug_errno(dev, errno, "Failed to call BTRFS_IOC_DEVICES_READY: %m");

        udev_builtin_add_property(event, "ID_BTRFS_READY", one_zero(r == 0));
        return 0;
}

const UdevBuiltin udev_builtin_btrfs = {
        .name = "btrfs",
        .cmd = builtin_btrfs,
        .help = "btrfs volume management",
};
