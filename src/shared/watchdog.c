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

#define DEFAULT_WATCHDOG_DEV "/dev/watchdog"

/* Starting from kernel version 4.5, the maximum allowable watchdog timeout is
 * UINT_MAX/1000U seconds (since internal calculations are done in milliseconds
 * using unsigned integers. However, the kernel's userspace API for the watchdog
 * uses signed integers for its ioctl parameters (even for timeout values and
 * bit flags) so this is why we must consider the maximum signed integer value
 * as well.
 */
#define WATCHDOG_TIMEOUT_MAX_SEC (CONST_MIN(UINT_MAX/1000U, (unsigned)INT_MAX))

static int saturated_usec_to_sec(usec_t val) {
        usec_t t = DIV_ROUND_UP(val, USEC_PER_SEC);
        return MIN(t, (usec_t) WATCHDOG_TIMEOUT_MAX_SEC); /* Saturate to watchdog max */
}

static int update_pretimeout(void) {
        int t_sec, pt_sec;

        if (watchdog_fd < 0)
                return 0;

        if (watchdog_pretimeout == USEC_INFINITY || watchdog_timeout == USEC_INFINITY)
                return 0;

        t_sec = saturated_usec_to_sec(watchdog_timeout);
        pt_sec = saturated_usec_to_sec(watchdog_pretimeout);
        if (pt_sec >= t_sec)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot set watchdog pretimeout to %is (%s watchdog timeout of %is)",
                                       pt_sec, pt_sec == t_sec ? "same as" : "longer than", t_sec);

        if (ioctl(watchdog_fd, WDIOC_SETPRETIMEOUT, &pt_sec) < 0) {
                /* EOPNOTSUPP means the watchdog does not support pretimeouts */
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_INFO : LOG_WARNING, errno,
                               "Failed to set pretimeout to %is: %m", pt_sec);
                return ERRNO_IS_NOT_SUPPORTED(errno) ? 0 : -errno;
        }

        /* The set ioctl does not return the actual value set, get it now */
        if (ioctl(watchdog_fd, WDIOC_GETPRETIMEOUT, &pt_sec) < 0)
                log_warning_errno(errno, "Failed to get pretimeout value, ignoring: %m");

        watchdog_pretimeout = (usec_t) pt_sec * USEC_PER_SEC;
        log_info("Set hardware watchdog pretimeout to %s.", FORMAT_TIMESPAN(watchdog_pretimeout, 0));

        return 0;
}

static int update_timeout(void) {
        if (watchdog_fd < 0)
                return 0;
        if (watchdog_timeout == USEC_INFINITY)
                return 0;

        if (watchdog_timeout == 0) {
                int flags;

                flags = WDIOS_DISABLECARD;
                if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0)
                        return log_warning_errno(errno, "Failed to disable hardware watchdog, ignoring: %m");
        } else {
                int sec, flags;

                sec = saturated_usec_to_sec(watchdog_timeout);
                if (ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &sec) < 0)
                        return log_warning_errno(errno, "Failed to set timeout to %is, ignoring: %m", sec);

                /* Just in case the driver is buggy */
                assert(sec > 0);

                /* watchdog_timeout stores the actual timeout used by the HW */
                watchdog_timeout = sec * USEC_PER_SEC;
                log_info("Set hardware watchdog to %s.", FORMAT_TIMESPAN(watchdog_timeout, 0));

                update_pretimeout();

                flags = WDIOS_ENABLECARD;
                if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0) {
                        /* ENOTTY means the watchdog is always enabled so we're fine */
                        log_full_errno(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to enable hardware watchdog, ignoring: %m");
                        if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                return -errno;
                }

                if (ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0) < 0)
                        return log_warning_errno(errno, "Failed to ping hardware watchdog, ignoring: %m");

                watchdog_last_ping = now(clock_boottime_or_monotonic());
        }

        return 0;
}

static int open_watchdog(void) {
        struct watchdog_info ident;
        const char *fn;

        if (watchdog_fd >= 0)
                return 0;

        fn = watchdog_device ?: DEFAULT_WATCHDOG_DEV;
        watchdog_fd = open(fn, O_WRONLY|O_CLOEXEC);
        if (watchdog_fd < 0)
                return log_debug_errno(errno, "Failed to open watchdog device %s, ignoring: %m", fn);

        if (ioctl(watchdog_fd, WDIOC_GETSUPPORT, &ident) < 0)
                log_debug_errno(errno, "Hardware watchdog %s does not support WDIOC_GETSUPPORT ioctl, ignorning: %m", fn);
        else
                log_info("Using hardware watchdog '%s', version %x, device %s",
                         ident.identity,
                         ident.firmware_version,
                         fn);

        return update_timeout();
}

int watchdog_set_device(const char *path) {
        int r;

        r = free_and_strdup(&watchdog_device, path);
        if (r < 0)
                return r;

        if (r > 0) /* watchdog_device changed */
                watchdog_fd = safe_close(watchdog_fd);

        return r;
}

int watchdog_setup_pretimeout(usec_t timeout) {
        /* Initialize the watchdog timeout with the caller value. This value is
         * going to be updated by update_pretimeout() with the closest value
         * supported by the driver */
        watchdog_pretimeout = timeout;

        /* If we didn't open the watchdog yet and didn't get any explicit
         * timeout value set, don't do anything */
        if (watchdog_fd < 0 && watchdog_pretimeout == USEC_INFINITY)
                return 0;

        return update_pretimeout();
}

int watchdog_setup(usec_t timeout) {
        /* Initialize the watchdog timeout with the caller value. This value is
         * going to be updated by update_timeout() with the closest value
         * supported by the driver */
        watchdog_timeout = timeout;

        /* If we didn't open the watchdog yet and didn't get any explicit
         * timeout value set, don't do anything */
        if (watchdog_fd < 0 && watchdog_timeout == USEC_INFINITY)
                return 0;

        if (watchdog_fd < 0)
                return open_watchdog();

        return update_timeout();
}

static usec_t calc_timeout(void) {
        /* Calculate the effective timeout which accounts for the watchdog
         * pretimeout if configured and supported.
         */
        if (timestamp_is_set(watchdog_pretimeout) && watchdog_timeout >= watchdog_pretimeout)
                return usec_sub_unsigned(watchdog_timeout, watchdog_pretimeout);
        else
                return watchdog_timeout;
}

usec_t watchdog_runtime_wait(void) {
        usec_t timeout = calc_timeout();
        if (!timestamp_is_set(timeout))
                return USEC_INFINITY;

        /* Sleep half the watchdog timeout since the last successful ping at most */
        if (timestamp_is_set(watchdog_last_ping)) {
                usec_t ntime = now(clock_boottime_or_monotonic());

                assert(ntime >= watchdog_last_ping);
                return usec_sub_unsigned(watchdog_last_ping + (watchdog_timeout / 2), ntime);
        }

        return timeout / 2;
}

int watchdog_ping(void) {
        usec_t ntime, timeout;

        if (!timestamp_is_set(watchdog_timeout))
                return 0;

        if (watchdog_fd < 0)
                /* open_watchdog() will automatically ping the device for us if necessary */
                return open_watchdog();

        ntime = now(clock_boottime_or_monotonic());
        timeout = calc_timeout();

        /* Never ping earlier than watchdog_timeout/4 and try to ping
         * by watchdog_timeout/2 plus scheduling latencies at the latest */
        if (timestamp_is_set(watchdog_last_ping)) {
                assert(ntime >= watchdog_last_ping);
                if ((ntime - watchdog_last_ping) < (timeout / 4))
                        return 0;
        }

        if (ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0) < 0)
                return log_warning_errno(errno, "Failed to ping hardware watchdog, ignoring: %m");

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
                        log_warning_errno(errno, "Failed to disable hardware watchdog, ignoring: %m");

                /* To be sure, use magic close logic, too */
                for (;;) {
                        static const char v = 'V';

                        if (write(watchdog_fd, &v, 1) > 0)
                                break;

                        if (errno != EINTR) {
                                log_warning_errno(errno, "Failed to disarm watchdog timer, ignoring: %m");
                                break;
                        }
                }
        }

        watchdog_fd = safe_close(watchdog_fd);

        /* Once closed, pinging the device becomes a NOP and we request a new
         * call to watchdog_setup() to open the device again. */
        watchdog_timeout = USEC_INFINITY;
}
