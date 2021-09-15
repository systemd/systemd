/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <unistd.h>
#include <linux/watchdog.h>

#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "time-util.h"
#include "watchdog.h"

static int watchdog_fd = -1;
static char *watchdog_device = NULL;
static usec_t watchdog_timeout = USEC_INFINITY;
static usec_t watchdog_last_ping = USEC_INFINITY;

static int update_timeout(void) {
        if (watchdog_fd < 0)
                return 0;
        if (watchdog_timeout == USEC_INFINITY)
                return 0;

        if (watchdog_timeout == 0) {
                int flags;

                flags = WDIOS_DISABLECARD;
                if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0)
                        return log_warning_errno(errno, "Failed to disable hardware watchdog: %m");
        } else {
                char buf[FORMAT_TIMESPAN_MAX];
                int sec, flags;
                usec_t t;

                t = DIV_ROUND_UP(watchdog_timeout, USEC_PER_SEC);
                sec = (int) t >= INT_MAX ? INT_MAX : t; /* Saturate */
                if (ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &sec) < 0)
                        return log_warning_errno(errno, "Failed to set timeout to %is: %m", sec);

                watchdog_timeout = (usec_t) sec * USEC_PER_SEC;
                log_info("Set hardware watchdog to %s.", format_timespan(buf, sizeof(buf), watchdog_timeout, 0));

                flags = WDIOS_ENABLECARD;
                if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0) {
                        /* ENOTTY means the watchdog is always enabled so we're fine */
                        log_full_errno(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to enable hardware watchdog, ignoring: %m");
                        if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                return -errno;
                }

                if (ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0) < 0)
                        return log_warning_errno(errno, "Failed to ping hardware watchdog: %m");

                watchdog_last_ping = now(clock_boottime_or_monotonic());
        }

        return 0;
}

static int open_watchdog(void) {
        struct watchdog_info ident;
        const char *fn;

        if (watchdog_fd >= 0)
                return 0;

        fn = watchdog_device ?: "/dev/watchdog";
        watchdog_fd = open(fn, O_WRONLY|O_CLOEXEC);
        if (watchdog_fd < 0)
                return log_debug_errno(errno, "Failed to open watchdog device %s: %m", fn);

        if (ioctl(watchdog_fd, WDIOC_GETSUPPORT, &ident) < 0)
                log_debug_errno(errno, "Hardware watchdog %s does not support WDIOC_GETSUPPORT ioctl: %m", fn);
        else
                log_info("Using hardware watchdog '%s', version %x, device %s",
                         ident.identity,
                         ident.firmware_version,
                         fn);

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

        /* If we didn't open the watchdog yet and didn't get any explicit timeout value set, don't do
         * anything */
        if (watchdog_fd < 0 && watchdog_timeout == USEC_INFINITY)
                return 0;

        if (watchdog_fd < 0)
                r = open_watchdog();
        else
                r = update_timeout();

        *usec = watchdog_timeout;
        return r;
}

usec_t watchdog_runtime_wait(void) {
        usec_t rtwait, ntime;

        if (!timestamp_is_set(watchdog_timeout))
                return USEC_INFINITY;

        /* Sleep half the watchdog timeout since the last successful ping at most */
        if (timestamp_is_set(watchdog_last_ping)) {
                ntime = now(clock_boottime_or_monotonic());
                assert(ntime >= watchdog_last_ping);
                rtwait = usec_sub_unsigned(watchdog_last_ping + (watchdog_timeout / 2), ntime);
        } else
                rtwait = watchdog_timeout / 2;

        return rtwait;
}

int watchdog_ping(void) {
        usec_t ntime;
        int r;

        ntime = now(clock_boottime_or_monotonic());

        /* Never ping earlier than watchdog_timeout/4 and try to ping
         * by watchdog_timeout/2 plus scheduling latencies the latest */
        if (timestamp_is_set(watchdog_last_ping)) {
                assert(ntime >= watchdog_last_ping);
                if ((ntime - watchdog_last_ping) < (watchdog_timeout / 4))
                        return 0;
        }

        if (watchdog_fd < 0) {
                r = open_watchdog();
                if (r < 0)
                        return r;
        }

        if (ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0) < 0)
                return log_warning_errno(errno, "Failed to ping hardware watchdog: %m");

        watchdog_last_ping = ntime;
        return 0;
}

void watchdog_close(bool disarm) {
        if (watchdog_fd < 0)
                return;

        if (disarm) {
                int flags;

                /* Explicitly disarm it */
                flags = WDIOS_DISABLECARD;
                if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0)
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
