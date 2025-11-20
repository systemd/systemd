/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "sd-login.h"

#include "acl-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "login-util.h"
#include "udev-builtin.h"

static int builtin_uaccess(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r, k;

        if (event->event_mode != EVENT_UDEV_WORKER) {
                log_device_debug(dev, "Running in test mode, skipping execution of 'uaccess' builtin command.");
                return 0;
        }

        umask(0022);

        /* don't muck around with ACLs when the system is not running systemd */
        if (!logind_running())
                return 0;

        _cleanup_close_ int fd = sd_device_open(dev, O_CLOEXEC|O_PATH);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(fd);
                log_device_full_errno(dev, ignore ? LOG_DEBUG : LOG_WARNING, fd,
                                      "Failed to open device node%s: %m",
                                      ignore ? ", ignoring" : "");
                return ignore ? 0 : fd;
        }

        const char *seat;
        r = device_get_seat(dev, &seat);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get seat: %m");

        uid_t uid;
        r = sd_seat_get_active(seat, /* ret_session = */ NULL, &uid);
        if (r < 0) {
                if (IN_SET(r, -ENXIO, -ENODATA))
                        /* No active session on this seat */
                        r = 0;
                else
                        log_device_error_errno(dev, r, "Failed to determine active user on seat %s: %m", seat);

                goto reset;
        }

        r = devnode_acl(fd, uid);
        if (r < 0) {
                log_device_full_errno(dev, r == -ENOENT ? LOG_DEBUG : LOG_ERR, r, "Failed to apply ACL: %m");
                goto reset;
        }

        return 0;

reset:
        /* Better be safe than sorry and reset ACL */
        k = devnode_acl(fd, /* uid = */ 0);
        if (k < 0)
                RET_GATHER(r, log_device_full_errno(dev, k == -ENOENT ? LOG_DEBUG : LOG_ERR, k, "Failed to flush ACLs: %m"));

        return r;
}

const UdevBuiltin udev_builtin_uaccess = {
        .name = "uaccess",
        .cmd = builtin_uaccess,
        .help = "Manage device node user ACL",
};
