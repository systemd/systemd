/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <unistd.h>
#include <linux/watchdog.h>

#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "time-util.h"
#include "watchdog.h"

static int watchdog_fd = -1;
static char *watchdog_device = NULL;
static usec_t watchdog_timeout = USEC_INFINITY;

static int update_timeout(void) {
        int r;

        if (watchdog_fd < 0)
                return 0;

        if (watchdog_timeout == USEC_INFINITY)
                return 0;
        else if (watchdog_timeout == 0) {
                int flags;

                flags = WDIOS_DISABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to disable hardware watchdog: %m");
        } else {
                int sec, flags;
                char buf[FORMAT_TIMESPAN_MAX];

                sec = (int) DIV_ROUND_UP(watchdog_timeout, USEC_PER_SEC);
                r = ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &sec);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to set timeout to %is: %m", sec);

                watchdog_timeout = (usec_t) sec * USEC_PER_SEC;
                log_info("Set hardware watchdog to %s.", format_timespan(buf, sizeof(buf), watchdog_timeout, 0));

                flags = WDIOS_ENABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0) {
                        /* ENOTTY means the watchdog is always enabled so we're fine */
                        log_full(errno == ENOTTY ? LOG_DEBUG : LOG_WARNING,
                                 "Failed to enable hardware watchdog: %m");
                        if (errno != ENOTTY)
                                return -errno;
                }

                r = ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to ping hardware watchdog: %m");
        }

        return 0;
}

static int open_watchdog(void) {
        struct watchdog_info ident;

        if (watchdog_fd >= 0)
                return 0;

        watchdog_fd = open(watchdog_device ?: "/dev/watchdog",
                           O_WRONLY|O_CLOEXEC);
        if (watchdog_fd < 0)
                return -errno;

        if (ioctl(watchdog_fd, WDIOC_GETSUPPORT, &ident) >= 0)
                log_info("Hardware watchdog '%s', version %x",
                         ident.identity,
                         ident.firmware_version);

        return update_timeout();
}

int watchdog_set_device(char *path) {
        int r;

        r = free_and_strdup(&watchdog_device, path);
        if (r < 0)
                return r;

        if (r > 0) /* watchdog_device changed */
                watchdog_fd = safe_close(watchdog_fd);

        return r;
}

int watchdog_set_timeout(usec_t *usec) {
        int r;

        watchdog_timeout = *usec;

        /* If we didn't open the watchdog yet and didn't get any
         * explicit timeout value set, don't do anything */
        if (watchdog_fd < 0 && watchdog_timeout == USEC_INFINITY)
                return 0;

        if (watchdog_fd < 0)
                r = open_watchdog();
        else
                r = update_timeout();

        *usec = watchdog_timeout;

        return r;
}

int watchdog_ping(void) {
        int r;

        if (watchdog_fd < 0) {
                r = open_watchdog();
                if (r < 0)
                        return r;
        }

        r = ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0);
        if (r < 0)
                return log_warning_errno(errno, "Failed to ping hardware watchdog: %m");

        return 0;
}

void watchdog_close(bool disarm) {
        int r;

        if (watchdog_fd < 0)
                return;

        if (disarm) {
                int flags;

                /* Explicitly disarm it */
                flags = WDIOS_DISABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0)
                        log_warning_errno(errno, "Failed to disable hardware watchdog: %m");

                /* To be sure, use magic close logic, too */
                for (;;) {
                        static const char v = 'V';

                        if (write(watchdog_fd, &v, 1) > 0)
                                break;

                        if (errno != EINTR) {
                                log_error_errno(errno, "Failed to disarm watchdog timer: %m");
                                break;
                        }
                }
        }

        watchdog_fd = safe_close(watchdog_fd);
}
