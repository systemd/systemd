/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "ethtool-util.h"
#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "udev-builtin.h"

static int builtin_net_driver_set_driver(UdevEvent *event, int argc, char **argv, bool test) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        _cleanup_close_ int ethtool_fd = -EBADF;
        _cleanup_free_ char *driver = NULL;
        const char *sysname;
        int r = 0;

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get sysname: %m");

        r = ethtool_get_driver(&ethtool_fd, sysname, &driver);
        if (r == -ENODEV || r == -ENOTSUP) {
                log_device_debug_errno(dev, r, "Failed to get driver for '%s': %m", sysname);
                return 0;
        }
        else if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get driver for '%s': %m", sysname);

        r = udev_builtin_add_property(event->dev, test, "ID_NET_DRIVER", driver);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to add ID_NET_DRIVER property, ignoring: %m");
        return 0;
}

const UdevBuiltin udev_builtin_net_driver = {
        .name = "net_driver",
        .cmd = builtin_net_driver_set_driver,
        .help = "Set driver for network device",
        .run_once = true,
};
