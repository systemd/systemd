/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * manage device node user ACL
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "sd-login.h"

#include "device-util.h"
#include "devnode-acl.h"
#include "login-util.h"
#include "log.h"
#include "udev-builtin.h"

static int builtin_uaccess(sd_device *dev, sd_netlink **rtnl, int argc, char *argv[], bool test) {
        const char *path = NULL, *seat;
        bool changed_acl = false;
        uid_t uid;
        int r;

        umask(0022);

        /* don't muck around with ACLs when the system is not running systemd */
        if (!logind_running())
                return 0;

        r = sd_device_get_devname(dev, &path);
        if (r < 0) {
                log_device_error_errno(dev, r, "Failed to get device name: %m");
                goto finish;
        }

        if (sd_device_get_property_value(dev, "ID_SEAT", &seat) < 0)
                seat = "seat0";

        r = sd_seat_get_active(seat, NULL, &uid);
        if (r < 0) {
                if (IN_SET(r, -ENXIO, -ENODATA))
                        /* No active session on this seat */
                        r = 0;
                else
                        log_device_error_errno(dev, r, "Failed to determine active user on seat %s: %m", seat);

                goto finish;
        }

        r = devnode_acl(path, true, false, 0, true, uid);
        if (r < 0) {
                log_device_full_errno(dev, r == -ENOENT ? LOG_DEBUG : LOG_ERR, r, "Failed to apply ACL: %m");
                goto finish;
        }

        changed_acl = true;
        r = 0;

finish:
        if (path && !changed_acl) {
                int k;

                /* Better be safe than sorry and reset ACL */
                k = devnode_acl(path, true, false, 0, false, 0);
                if (k < 0) {
                        log_device_full_errno(dev, k == -ENOENT ? LOG_DEBUG : LOG_ERR, k, "Failed to apply ACL: %m");
                        if (r >= 0)
                                r = k;
                }
        }

        return r;
}

const UdevBuiltin udev_builtin_uaccess = {
        .name = "uaccess",
        .cmd = builtin_uaccess,
        .help = "Manage device node user ACL",
};
