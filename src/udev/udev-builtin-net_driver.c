/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "ethtool-util.h"
#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "udev-builtin.h"

static int builtin_net_driver_set_driver(UdevEvent *event, int argc, char **argv) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        _cleanup_close_ int ethtool_fd = -EBADF;
        _cleanup_free_ char *driver = NULL;
        const char *sysname;
        int r;

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get sysname: %m");

        r = ethtool_get_driver(&ethtool_fd, sysname, &driver);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_device_debug_errno(dev, r, "Querying driver name via ethtool API is not supported by device '%s', ignoring: %m", sysname);
                return 0;
        }
        if (r == -ENODEV) {
                log_device_debug_errno(dev, r, "Device already vanished, ignoring.");
                return 0;
        }
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get driver for '%s': %m", sysname);

        return udev_builtin_add_property(event, "ID_NET_DRIVER", driver);
}

const UdevBuiltin udev_builtin_net_driver = {
        .name = "net_driver",
        .cmd = builtin_net_driver_set_driver,
        .help = "Set driver for network device",
        .run_once = true,
};
