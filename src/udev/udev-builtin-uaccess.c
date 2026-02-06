/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "sd-login.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "login-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"
#include "user-util.h"

static int builtin_uaccess(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        _cleanup_strv_free_ char **sessions = NULL;
        _cleanup_set_free_ Set *uids = NULL;
        uid_t uid;
        int r = 0, k;

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

        r = sd_device_has_tag(dev, "uaccess");
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to query uaccess tag: %m");

        if (r > 0) {
                const char *seat;
                r = device_get_seat(dev, &seat);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to get seat: %m");

                r = sd_seat_get_active(seat, /* ret_session= */ NULL, &uid);
                if (IN_SET(r, -ENXIO, -ENODATA))
                        /* No active session on this seat */
                        r = 0;
                else if (r < 0)
                        log_device_error_errno(dev, r, "Failed to determine active user on seat %s, ignoring: %m", seat);
                else {
                        if (set_ensure_put(&uids, NULL, UID_TO_PTR(uid)) < 0)
                                return log_oom();
                }
        }

        r = sd_device_has_tag(dev, "xaccess");
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to query device xaccess tag: %m");

        if (r > 0) {
                r = sd_get_sessions(&sessions);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to list sessions: %m");

                STRV_FOREACH(s, sessions) {
                        _cleanup_free_ char *state = NULL;
                        if (sd_session_get_state(*s, &state) < 0) {
                                log_device_debug_errno(dev, r, "Failed to query state for session %s, ignoring: %m", *s);
                                continue;
                        }
                        if (streq(state, "closing"))
                                continue;
                        r = sd_session_has_extra_device_access(*s);
                        if (r < 0) {
                                log_device_debug_errno(dev, r, "Failed to query extra device access for session %s, ignoring: %m", *s);
                                continue;
                        }
                        if (r == 0)
                                continue;
                        if (sd_session_get_uid(*s, &uid) < 0) {
                                log_device_debug_errno(dev, r, "Failed to query uid for session %s, ignoring: %m", *s);
                                continue;
                        }
                        if (set_ensure_put(&uids, NULL, UID_TO_PTR(uid)) < 0)
                                return log_oom();
                }
        }

        r = devnode_acl(fd, uids);
        if (r < 0) {
                log_device_full_errno(dev, r == -ENOENT ? LOG_DEBUG : LOG_ERR, r, "Failed to apply ACL: %m");
                goto reset;
        }

        return 0;

reset:
        /* Better be safe than sorry and reset ACL */
        k = devnode_acl(fd, /* uids= */ NULL);
        if (k < 0)
                RET_GATHER(r, log_device_full_errno(dev, k == -ENOENT ? LOG_DEBUG : LOG_ERR, k, "Failed to flush ACLs: %m"));

        return r;
}

const UdevBuiltin udev_builtin_uaccess = {
        .name = "uaccess",
        .cmd = builtin_uaccess,
        .help = "Manage device node user ACL",
};
