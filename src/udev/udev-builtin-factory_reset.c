/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-util.h"
#include "factory-reset.h"
#include "string-util.h"
#include "udev-builtin.h"

/* Sometimes it is relevant in udev rules to know whether factory reset is currently in effect or not. Report
 * the current state at moment of probing as a udev property. This can be used to create certain device node
 * symlinks only once factory reset is complete, or even mark whole devices as SYSTEMD_READY=0 as long as
 * factory reset is still ongoing. */

static int builtin_factory_reset(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);

        if (argc != 2 || !streq(argv[1], "status"))
                return log_device_warning_errno(
                                dev, SYNTHETIC_ERRNO(EINVAL), "%s: expected: status", argv[0]);

        /* Report factory reset mode at the moment of probing a device. */
        FactoryResetMode f = factory_reset_mode();
        if (f < 0) {
                log_device_debug_errno(dev, f, "Unable to detect factory reset mode, ignoring: %m");
                return 0;
        }

        return udev_builtin_add_property(event, "ID_FACTORY_RESET", factory_reset_mode_to_string(f));
}

const UdevBuiltin udev_builtin_factory_reset = {
        .name = "factory_reset",
        .cmd = builtin_factory_reset,
        .help = "Factory Reset Mode",
        .run_once = true,
};
