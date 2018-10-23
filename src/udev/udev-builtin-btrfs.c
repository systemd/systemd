/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#if HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "fd-util.h"
#include "missing.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-builtin.h"
#include "util.h"

static int builtin_btrfs(sd_device *dev, int argc, char *argv[], bool test) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_close_ int fd = -1;
        int r;

        if (argc != 3 || !streq(argv[1], "ready"))
                return -EINVAL;

        fd = open("/dev/btrfs-control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        strscpy(args.name, sizeof(args.name), argv[2]);
        r = ioctl(fd, BTRFS_IOC_DEVICES_READY, &args);
        if (r < 0)
                return -errno;

        udev_builtin_add_property(dev, test, "ID_BTRFS_READY", one_zero(r == 0));
        return 0;
}

const struct udev_builtin udev_builtin_btrfs = {
        .name = "btrfs",
        .cmd = builtin_btrfs,
        .help = "btrfs volume management",
};
