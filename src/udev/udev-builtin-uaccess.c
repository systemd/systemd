/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * manage device node user ACL
 */

#include "sd-login.h"

#include "acl-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "login-util.h"
#include "udev-builtin.h"

static int devnode_acl(int fd, uid_t uid) {
        bool changed = false, found = false;
        int r;

        assert(fd >= 0);

        _cleanup_(acl_freep) acl_t acl = NULL;
        acl = acl_get_fd(fd);
        if (!acl)
                return -errno;

        acl_entry_t entry;
        for (r = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
             r > 0;
             r = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry)) {

                acl_tag_t tag;
                if (acl_get_tag_type(entry, &tag) < 0)
                        return -errno;

                if (tag != ACL_USER)
                        continue;

                if (uid > 0) {
                        uid_t *u = acl_get_qualifier(entry);
                        if (!u)
                                return -errno;

                        if (*u == uid) {
                                acl_permset_t permset;
                                if (acl_get_permset(entry, &permset) < 0)
                                        return -errno;

                                int rd = acl_get_perm(permset, ACL_READ);
                                if (rd < 0)
                                        return -errno;

                                int wt = acl_get_perm(permset, ACL_WRITE);
                                if (wt < 0)
                                        return -errno;

                                if (!rd || !wt) {
                                        if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0)
                                                return -errno;

                                        changed = true;
                                }

                                found = true;
                                continue;
                        }
                }

                if (acl_delete_entry(acl, entry) < 0)
                        return -errno;

                changed = true;
        }
        if (r < 0)
                return -errno;

        if (!found && uid > 0) {
                if (acl_create_entry(&acl, &entry) < 0)
                        return -errno;

                if (acl_set_tag_type(entry, ACL_USER) < 0)
                        return -errno;

                if (acl_set_qualifier(entry, &uid) < 0)
                        return -errno;

                acl_permset_t permset;
                if (acl_get_permset(entry, &permset) < 0)
                        return -errno;

                if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0)
                        return -errno;

                changed = true;
        }

        if (!changed)
                return 0;

        if (acl_calc_mask(&acl) < 0)
                return -errno;

        if (acl_set_fd(fd, acl) < 0)
                return -errno;

        return 0;
}

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

        _cleanup_close_ int fd = sd_device_open(dev, O_CLOEXEC|O_RDWR);
        if (fd < 0)
                return log_device_error_errno(dev, fd, "Failed to open device node: %m");

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
