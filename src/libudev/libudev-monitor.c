/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>

#include "libudev.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "device-monitor-private.h"
#include "errno-util.h"
#include "io-util.h"
#include "libudev-device-internal.h"
#include "string-util.h"

/**
 * SECTION:libudev-monitor
 * @short_description: device event source
 *
 * Connects to a device event source.
 */

/**
 * udev_monitor:
 *
 * Opaque object handling an event source.
 */
struct udev_monitor {
        struct udev *udev;
        unsigned n_ref;
        sd_device_monitor *monitor;
};

static MonitorNetlinkGroup monitor_netlink_group_from_string(const char *name) {
        if (!name)
                return MONITOR_GROUP_NONE;
        if (streq(name, "udev"))
                return MONITOR_GROUP_UDEV;
        if (streq(name, "kernel"))
                return MONITOR_GROUP_KERNEL;
        return _MONITOR_NETLINK_GROUP_INVALID;
}

/**
 * udev_monitor_new_from_netlink:
 * @udev: udev library context
 * @name: name of event source
 *
 * Create new udev monitor and connect to a specified event
 * source. Valid sources identifiers are "udev" and "kernel".
 *
 * Applications should usually not connect directly to the
 * "kernel" events, because the devices might not be usable
 * at that time, before udev has configured them, and created
 * device nodes. Accessing devices at the same time as udev,
 * might result in unpredictable behavior. The "udev" events
 * are sent out after udev has finished its event processing,
 * all rules have been processed, and needed device nodes are
 * created.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev monitor.
 *
 * Returns: a new udev monitor, or #NULL, in case of an error
 **/
_public_ struct udev_monitor* udev_monitor_new_from_netlink(struct udev *udev, const char *name) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        struct udev_monitor *udev_monitor;
        MonitorNetlinkGroup g;
        int r;

        g = monitor_netlink_group_from_string(name);
        if (g < 0)
                return_with_errno(NULL, EINVAL);

        r = device_monitor_new_full(&m, g, -EBADF);
        if (r < 0)
                return_with_errno(NULL, r);

        udev_monitor = new(struct udev_monitor, 1);
        if (!udev_monitor)
                return_with_errno(NULL, ENOMEM);

        *udev_monitor = (struct udev_monitor) {
                .udev = udev,
                .n_ref = 1,
                .monitor = TAKE_PTR(m),
        };

        return udev_monitor;
}

/**
 * udev_monitor_filter_update:
 * @udev_monitor: monitor
 *
 * Update the installed socket filter. This is only needed,
 * if the filter was removed or changed.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_update(struct udev_monitor *udev_monitor) {
        assert_return(udev_monitor, -EINVAL);

        return sd_device_monitor_filter_update(udev_monitor->monitor);
}

/**
 * udev_monitor_enable_receiving:
 * @udev_monitor: the monitor which should receive events
 *
 * Deprecated, and alias of udev_monitor_filter_update().
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor) {
        return udev_monitor_filter_update(udev_monitor);
}

/**
 * udev_monitor_set_receive_buffer_size:
 * @udev_monitor: the monitor which should receive events
 * @size: the size in bytes
 *
 * Set the size of the kernel socket buffer. This call needs the
 * appropriate privileges to succeed.
 *
 * Returns: 0 on success, otherwise -1 on error.
 */
_public_ int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size) {
        assert_return(udev_monitor, -EINVAL);

        return sd_device_monitor_set_receive_buffer_size(udev_monitor->monitor, (size_t) size);
}

static struct udev_monitor* udev_monitor_free(struct udev_monitor *udev_monitor) {
        assert(udev_monitor);

        sd_device_monitor_unref(udev_monitor->monitor);
        return mfree(udev_monitor);
}

/**
 * udev_monitor_ref:
 * @udev_monitor: udev monitor
 *
 * Take a reference of a udev monitor.
 *
 * Returns: the passed udev monitor
 **/

/**
 * udev_monitor_unref:
 * @udev_monitor: udev monitor
 *
 * Drop a reference of a udev monitor. If the refcount reaches zero,
 * the bound socket will be closed, and the resources of the monitor
 * will be released.
 *
 * Returns: #NULL
 **/
DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(struct udev_monitor, udev_monitor, udev_monitor_free);

/**
 * udev_monitor_get_udev:
 * @udev_monitor: udev monitor
 *
 * Retrieve the udev library context the monitor was created with.
 *
 * Returns: the udev library context
 **/
_public_ struct udev* udev_monitor_get_udev(struct udev_monitor *udev_monitor) {
        assert_return(udev_monitor, NULL);

        return udev_monitor->udev;
}

/**
 * udev_monitor_get_fd:
 * @udev_monitor: udev monitor
 *
 * Retrieve the socket file descriptor associated with the monitor.
 *
 * Returns: the socket file descriptor
 **/
_public_ int udev_monitor_get_fd(struct udev_monitor *udev_monitor) {
        assert_return(udev_monitor, -EINVAL);

        return sd_device_monitor_get_fd(udev_monitor->monitor);
}

static int udev_monitor_receive_sd_device(struct udev_monitor *udev_monitor, sd_device **ret) {
        int r;

        assert(udev_monitor);
        assert(ret);

        for (;;) {
                /* r == 0 means a device is received but it does not pass the current filter. */
                r = sd_device_monitor_receive(udev_monitor->monitor, ret);
                if (r != 0)
                        return r;

                for (;;) {
                        /* Wait for next message */
                        r = fd_wait_for_event(sd_device_monitor_get_fd(udev_monitor->monitor), POLLIN, 0);
                        if (r == -EINTR)
                                continue;
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EAGAIN;

                        /* Receive next message */
                        break;
                }
        }
}

/**
 * udev_monitor_receive_device:
 * @udev_monitor: udev monitor
 *
 * Receive data from the udev monitor socket, allocate a new udev
 * device, fill in the received data, and return the device.
 *
 * Only socket connections with uid=0 are accepted.
 *
 * The monitor socket is by default set to NONBLOCK. A variant of poll() on
 * the file descriptor returned by udev_monitor_get_fd() should to be used to
 * wake up when new devices arrive, or alternatively the file descriptor
 * switched into blocking mode.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, in case of an error
 **/
_public_ struct udev_device* udev_monitor_receive_device(struct udev_monitor *udev_monitor) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        int r;

        assert_return(udev_monitor, NULL);

        r = udev_monitor_receive_sd_device(udev_monitor, &device);
        if (r < 0)
                return_with_errno(NULL, r);

        return udev_device_new(udev_monitor->udev, device);
}

/**
 * udev_monitor_filter_add_match_subsystem_devtype:
 * @udev_monitor: the monitor
 * @subsystem: the subsystem value to match the incoming devices against
 * @devtype: the devtype value to match the incoming devices against
 *
 * This filter is efficiently executed inside the kernel, and libudev subscribers
 * will usually not be woken up for devices which do not match.
 *
 * The filter must be installed before the monitor is switched to listening mode.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *udev_monitor, const char *subsystem, const char *devtype) {
        int r;

        assert_return(udev_monitor, -EINVAL);

        r = sd_device_monitor_filter_add_match_subsystem_devtype(udev_monitor->monitor, subsystem, devtype);
        return r < 0 ? r : 0;
}

/**
 * udev_monitor_filter_add_match_tag:
 * @udev_monitor: the monitor
 * @tag: the name of a tag
 *
 * This filter is efficiently executed inside the kernel, and libudev subscribers
 * will usually not be woken up for devices which do not match.
 *
 * The filter must be installed before the monitor is switched to listening mode.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_add_match_tag(struct udev_monitor *udev_monitor, const char *tag) {
        int r;

        assert_return(udev_monitor, -EINVAL);

        r = sd_device_monitor_filter_add_match_tag(udev_monitor->monitor, tag);
        return r < 0 ? r : 0;
}

/**
 * udev_monitor_filter_remove:
 * @udev_monitor: monitor
 *
 * Remove all filters from monitor.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_remove(struct udev_monitor *udev_monitor) {
        assert_return(udev_monitor, -EINVAL);

        return sd_device_monitor_filter_remove(udev_monitor->monitor);
}
