/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-list.h"
#include "errno-util.h"
#include "signal-util.h"
#include "udev-error.h"

int device_add_errno(sd_device *dev, int error) {
        int r;

        assert(dev);

        if (error == 0)
                return 0;

        error = ABS(error);

        r = device_add_property(dev, "UDEV_WORKER_FAILED", "1");
        RET_GATHER(r, device_add_propertyf(dev, "UDEV_WORKER_ERRNO", "%i", error));

        const char *str = errno_name_no_fallback(error);
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

int device_broadcast_on_error(sd_device *dev, sd_device_monitor *monitor) {
        int r;

        assert(dev);
        assert(monitor);

        /* delete state from disk */
        (void) device_delete_db(dev);
        (void) device_tag_index(dev, /* add= */ false);

        r = device_monitor_send(monitor, /* destination= */ NULL, dev);
        if (r < 0) {
                uint64_t seqnum = 0;

                (void) sd_device_get_seqnum(dev, &seqnum);
                return log_device_warning_errno(dev, r, "Failed to broadcast event (SEQNUM=%"PRIu64") to libudev listeners: %m", seqnum);
        }

        return 0;
}
