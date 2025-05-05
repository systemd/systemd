/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-private.h"
#include "errno-list.h"
#include "errno-util.h"
#include "signal-util.h"
#include "udev-error.h"

int device_add_errno(sd_device *dev, int error) {
        int r;

        assert(dev);

        if (error == 0)
                return 0;

        error = abs(error);

        r = device_add_property(dev, "UDEV_WORKER_FAILED", "1");
        RET_GATHER(r, device_add_propertyf(dev, "UDEV_WORKER_ERRNO", "%i", error));

        const char *str = errno_to_name(error);
        if (str)
                RET_GATHER(r, device_add_property(dev, "UDEV_WORKER_ERRNO_NAME", str));

        return r;
}

int device_add_exit_status(sd_device *dev, int status) {
        int r;

        assert(dev);

        if (status == 0)
                return 0;

        r = device_add_property(dev, "UDEV_WORKER_FAILED", "1");
        return RET_GATHER(r, device_add_propertyf(dev, "UDEV_WORKER_EXIT_STATUS", "%i", status));
}

int device_add_signal(sd_device *dev, int signo) {
        int r;

        assert(dev);

        r = device_add_property(dev, "UDEV_WORKER_FAILED", "1");
        RET_GATHER(r, device_add_propertyf(dev, "UDEV_WORKER_SIGNAL", "%i", signo));

        const char *str = signal_to_string(signo);
        if (str)
                RET_GATHER(r, device_add_property(dev, "UDEV_WORKER_SIGNAL_NAME", str));

        return r;
}
