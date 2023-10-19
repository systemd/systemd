#include "alloc-util.h"
#include "device-util.h"
#include "escape.h"
#include "errno-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"
#include "ethtool-util.h"
#include "fd-util.h"


static int builtin_net_driver_set_driver(UdevEvent *event, int argc, char **argv, bool test) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        _cleanup_free_ char *driver = NULL;
        const char *sysname = NULL;
        int ethtool_fd = -EBADF;
        int r = 0;

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get sysname: %m");

        r = ethtool_get_driver(&ethtool_fd, sysname, &driver);
        safe_close(ethtool_fd);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get driver for '%s': %m", sysname);

        udev_builtin_add_property(event->dev, test, "ID_NET_DRIVER", driver);
        return 0;
}

const UdevBuiltin udev_builtin_net_driver = {
        .name = "net_driver",
        .cmd = builtin_net_driver_set_driver,
        .help = "Set driver for network device",
        .run_once = true,
};
