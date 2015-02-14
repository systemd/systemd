/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "missing.h"
#include "udev.h"

static int builtin_btrfs(struct udev_device *dev, int argc, char *argv[], bool test) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_close_ int fd = -1;
        int err;

        if (argc != 3 || !streq(argv[1], "ready"))
                return EXIT_FAILURE;

        fd = open("/dev/btrfs-control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return EXIT_FAILURE;

        strscpy(args.name, sizeof(args.name), argv[2]);
        err = ioctl(fd, BTRFS_IOC_DEVICES_READY, &args);
        if (err < 0)
                return EXIT_FAILURE;

        udev_builtin_add_property(dev, test, "ID_BTRFS_READY", one_zero(err == 0));
        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_btrfs = {
        .name = "btrfs",
        .cmd = builtin_btrfs,
        .help = "btrfs volume management",
};
