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
static usec_t watchdog_pretimeout = USEC_INFINITY;
static usec_t watchdog_last_ping = USEC_INFINITY;

static unsigned int usec_to_sec(usec_t val) {
        usec_t t = DIV_ROUND_UP(val, USEC_PER_SEC);
        return (unsigned int) t >= (UINT_MAX / 1000) ? (UINT_MAX / 1000) : t; /* Saturate to watchdog max */
}

static int update_pretimeout(void) {
        int r;

        if (watchdog_fd < 0)
                return 0;

        if (watchdog_pretimeout == USEC_INFINITY || watchdog_timeout == USEC_INFINITY)
                return 0;
        else if (usec_to_sec(watchdog_pretimeout) >= usec_to_sec(watchdog_timeout)) {
                unsigned int t_sec = usec_to_sec(watchdog_timeout);
                unsigned int pt_sec = usec_to_sec(watchdog_pretimeout);
                log_error("Cannot set watchdog pretimeout to %us (%s watchdog timeout of %us)",
                          pt_sec, pt_sec == t_sec ? "same as" : "longer than", t_sec);
                return -EINVAL;
        } else {
                char buf[FORMAT_TIMESPAN_MAX];
                unsigned int sec = usec_to_sec(watchdog_pretimeout);

                r = ioctl(watchdog_fd, WDIOC_SETPRETIMEOUT, &sec);
                if (r < 0) {
                        /* EOPNOTSUPP means the watchdog does not support pretimeouts */
                        log_full(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_INFO : LOG_WARNING,
                                 "Failed to set pretimeout to %us: %m", sec);
                        return (ERRNO_IS_NOT_SUPPORTED(errno) ? 0 : -errno);
                }

                /* The set ioctl does not return the actual value set, get it now */
                if (ioctl(watchdog_fd, WDIOC_GETPRETIMEOUT, &sec))
                        log_warning_errno(errno, "Failed to get pretimeout value: %m");

                watchdog_pretimeout = (usec_t) sec * USEC_PER_SEC;
                log_info("Set hardware watchdog pretimeout to %s.",
                         format_timespan(buf, sizeof(buf), watchdog_pretimeout, 0));
        }

        return 0;
}

static int update_timeout(void) {
        if (watchdog_fd < 0)
                return 0;
        if (watchdog_timeout == USEC_INFINITY)
                return 0;

        if (watchdog_timeout == 0) {
                unsigned int flags;

                flags = WDIOS_DISABLECARD;
                if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0)
                        return log_warning_errno(errno, "Failed to disable hardware watchdog: %m");
        } else {
                char buf[FORMAT_TIMESPAN_MAX];
                unsigned int sec, flags;

                sec = usec_to_sec(watchdog_timeout);
                if (ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &sec) < 0)
                        return log_warning_errno(errno, "Failed to set timeout to %us: %m", sec);

                watchdog_timeout = (usec_t) sec * USEC_PER_SEC;
                log_info("Set hardware watchdog to %s.", format_timespan(buf, sizeof(buf), watchdog_timeout, 0));

                update_pretimeout();

                flags = WDIOS_ENABLECARD;
                if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0) {
                        /* ENOTTY means the watchdog is always enabled so we're fine */
                        log_full(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_DEBUG : LOG_WARNING,
                                 "Failed to enable hardware watchdog: %m");
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

int watchdog_set_pretimeout(usec_t *usec) {
        int r;

        watchdog_pretimeout = *usec;

        /* If we didn't open the watchdog yet and didn't get any explicit timeout value set, don't do
         * anything */
        if (watchdog_fd < 0 && watchdog_pretimeout == USEC_INFINITY)
                return 0;

        r = update_pretimeout();

        *usec = watchdog_pretimeout;
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
        usec_t rtwait, ntime, timeout;

        if (!timestamp_is_set(watchdog_timeout))
                return USEC_INFINITY;

        if (timestamp_is_set(watchdog_pretimeout) && watchdog_timeout >= watchdog_pretimeout)
                timeout = usec_sub_unsigned(watchdog_timeout, watchdog_pretimeout);
        else
                timeout = watchdog_timeout;

        /* Sleep half the watchdog timeout since the last successful ping at most */
        if (timestamp_is_set(watchdog_last_ping)) {
                ntime = now(clock_boottime_or_monotonic());
                assert(ntime >= watchdog_last_ping);
                rtwait = usec_sub_unsigned(watchdog_last_ping + (timeout / 2), ntime);
        } else
                rtwait = timeout / 2;

        return rtwait;
}

int watchdog_ping(void) {
        usec_t ntime, timeout;
        int r;

        ntime = now(clock_boottime_or_monotonic());

        if (timestamp_is_set(watchdog_pretimeout) && watchdog_timeout >= watchdog_pretimeout)
                timeout = usec_sub_unsigned(watchdog_timeout, watchdog_pretimeout);
        else
                timeout = watchdog_timeout;

        /* Never ping earlier than watchdog_timeout/4 and try to ping
         * by watchdog_timeout/2 plus scheduling latencies the latest */
        if (timestamp_is_set(watchdog_last_ping)) {
                assert(ntime >= watchdog_last_ping);
                if ((ntime - watchdog_last_ping) < (timeout / 4))
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
                unsigned int flags;

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
