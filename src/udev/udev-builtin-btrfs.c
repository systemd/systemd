/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/btrfs.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-builtin.h"
#include "util.h"

static int builtin_btrfs(sd_device *dev, sd_netlink **rtnl, int argc, char *argv[], bool test) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_close_ int fd = -1;
        int r;

        if (argc != 3 || !streq(argv[1], "ready"))
                return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invalid arguments");

        fd = open("/dev/btrfs-control", O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                if (ERRNO_IS_DEVICE_ABSENT(errno)) {
                        /* Driver not installed? Then we aren't ready. This is useful in initrds that lack
                         * btrfs.ko. After the host transition (where btrfs.ko will hopefully become
                         * available) the device can be retriggered and will then be considered ready. */
                        udev_builtin_add_property(dev, test, "ID_BTRFS_READY", "0");
                        return 0;
                }

                return log_device_debug_errno(dev, errno, "Failed to open /dev/btrfs-control: %m");
        }

        strscpy(args.name, sizeof(args.name), argv[2]);
        r = ioctl(fd, BTRFS_IOC_DEVICES_READY, &args);
        if (r < 0)
                return log_device_debug_errno(dev, errno, "Failed to call BTRFS_IOC_DEVICES_READY: %m");

        udev_builtin_add_property(dev, test, "ID_BTRFS_READY", one_zero(r == 0));
        return 0;
}

const UdevBuiltin udev_builtin_btrfs = {
        .name = "btrfs",
        .cmd = builtin_btrfs,
        .help = "btrfs volume management",
};
