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
#include "path-util.h"
#include "string-util.h"
#include "time-util.h"
#include "watchdog.h"

static int watchdog_fd = -1;
static char *watchdog_device;
static usec_t watchdog_timeout; /* 0 → close device and USEC_INFINITY → don't change timeout */
static usec_t watchdog_last_ping = USEC_INFINITY;

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

static int watchdog_set_enable(bool enable) {
        int flags = enable ? WDIOS_ENABLECARD : WDIOS_DISABLECARD;

        assert(watchdog_fd >= 0);

        if (ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags) < 0) {
                if (!enable)
                        return log_warning_errno(errno, "Failed to disable hardware watchdog, ignoring: %m");

                /* ENOTTY means the watchdog is always enabled so we're fine */
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to enable hardware watchdog, ignoring: %m");
                if (!ERRNO_IS_NOT_SUPPORTED(errno))
                        return -errno;
        }

        return 0;
}

static int watchdog_get_timeout(void) {
        int sec = 0;

        assert(watchdog_fd >= 0);

        if (ioctl(watchdog_fd, WDIOC_GETTIMEOUT, &sec) < 0)
                return -errno;

        assert(sec > 0);
        watchdog_timeout = sec * USEC_PER_SEC;

        return 0;
}

static int watchdog_set_timeout(void) {
        int sec;

        assert(watchdog_fd >= 0);
        assert(timestamp_is_set(watchdog_timeout));

        sec = saturated_usec_to_sec(watchdog_timeout);

        if (ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &sec) < 0)
                return -errno;

        assert(sec > 0); /* buggy driver ? */
        watchdog_timeout = sec * USEC_PER_SEC;

        return 0;
}

static int watchdog_ping_now(void) {
        assert(watchdog_fd >= 0);

        if (ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0) < 0)
                return log_warning_errno(errno, "Failed to ping hardware watchdog, ignoring: %m");

        watchdog_last_ping = now(clock_boottime_or_monotonic());

        return 0;
}

static int update_timeout(void) {
        int r;

        assert(watchdog_timeout > 0);

        if (watchdog_fd < 0)
                return 0;

        if (watchdog_timeout != USEC_INFINITY) {
                r = watchdog_set_timeout();
                if (r < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(r))
                                return log_error_errno(r, "Failed to set timeout to %s: %m",
                                                       FORMAT_TIMESPAN(watchdog_timeout, 0));

                        log_info("Modifying watchdog timeout is not supported, reusing the programmed timeout.");
                        watchdog_timeout = USEC_INFINITY;
                }
        }

        if (watchdog_timeout == USEC_INFINITY) {
                r = watchdog_get_timeout();
                if (r < 0)
                        return log_error_errno(r, "Failed to query watchdog HW timeout: %m");
        }

        r = watchdog_set_enable(true);
        if (r < 0)
                return r;

        log_info("Watchdog running with a timeout of %s.", FORMAT_TIMESPAN(watchdog_timeout, 0));

        return watchdog_ping_now();
}

static int open_watchdog(void) {
        struct watchdog_info ident;
        const char *fn;
        int r;

        if (watchdog_fd >= 0)
                return 0;

        /* Let's prefer new-style /dev/watchdog0 (i.e. kernel 3.5+) over classic /dev/watchdog. The former
         * has the benefit that we can easily find the matching directory in sysfs from it, as the relevant
         * sysfs attributes can only be found via /sys/dev/char/<major>:<minor> if the new-style device
         * major/minor is used, not the old-style. */
        fn = !watchdog_device || path_equal(watchdog_device, "/dev/watchdog") ?
                "/dev/watchdog0" : watchdog_device;

        r = free_and_strdup(&watchdog_device, fn);
        if (r < 0)
                return log_oom_debug();

        watchdog_fd = open(watchdog_device, O_WRONLY|O_CLOEXEC);
        if (watchdog_fd < 0)
                return log_debug_errno(errno, "Failed to open watchdog device %s, ignoring: %m", watchdog_device);

        if (ioctl(watchdog_fd, WDIOC_GETSUPPORT, &ident) < 0)
                log_debug_errno(errno, "Hardware watchdog %s does not support WDIOC_GETSUPPORT ioctl, ignoring: %m", watchdog_device);
        else
                log_info("Using hardware watchdog '%s', version %x, device %s",
                         ident.identity,
                         ident.firmware_version,
                         watchdog_device);

        r = update_timeout();
        if (r < 0)
                watchdog_close(true);

        return r;
}

int watchdog_set_device(const char *path) {
        int r;

        r = free_and_strdup(&watchdog_device, path);
        if (r > 0) /* watchdog_device changed */
                watchdog_fd = safe_close(watchdog_fd);

        return r;
}

int watchdog_setup(usec_t timeout) {
        usec_t previous_timeout;
        int r;

        /* timeout=0 closes the device whereas passing timeout=USEC_INFINITY opens it (if needed)
         * without configuring any particular timeout and thus reuses the programmed value (therefore
         * it's a nop if the device is already opened). */

        if (timeout == 0) {
                watchdog_close(true);
                return 0;
        }

        /* Let's shortcut duplicated requests */
        if (watchdog_fd >= 0 && (timeout == watchdog_timeout || timeout == USEC_INFINITY))
                return 0;

        /* Initialize the watchdog timeout with the caller value. This value is going to be updated by
         * update_timeout() with the closest value supported by the driver */
        previous_timeout = watchdog_timeout;
        watchdog_timeout = timeout;

        if (watchdog_fd < 0)
                return open_watchdog();

        r = update_timeout();
        if (r < 0)
                watchdog_timeout = previous_timeout;

        return r;
}

usec_t watchdog_runtime_wait(void) {

        if (!timestamp_is_set(watchdog_timeout))
                return USEC_INFINITY;

        /* Sleep half the watchdog timeout since the last successful ping at most */
        if (timestamp_is_set(watchdog_last_ping)) {
                usec_t ntime = now(clock_boottime_or_monotonic());

                assert(ntime >= watchdog_last_ping);
                return usec_sub_unsigned(watchdog_last_ping + (watchdog_timeout / 2), ntime);
        }

        return watchdog_timeout / 2;
}

int watchdog_ping(void) {
        usec_t ntime;

        if (watchdog_timeout == 0)
                return 0;

        if (watchdog_fd < 0)
                /* open_watchdog() will automatically ping the device for us if necessary */
                return open_watchdog();

        ntime = now(clock_boottime_or_monotonic());

        /* Never ping earlier than watchdog_timeout/4 and try to ping
         * by watchdog_timeout/2 plus scheduling latencies the latest */
        if (timestamp_is_set(watchdog_last_ping)) {
                assert(ntime >= watchdog_last_ping);
                if ((ntime - watchdog_last_ping) < (watchdog_timeout / 4))
                        return 0;
        }

        return watchdog_ping_now();
}

void watchdog_close(bool disarm) {

        /* Once closed, pinging the device becomes a NOP and we request a new
         * call to watchdog_setup() to open the device again. */
        watchdog_timeout = 0;

        if (watchdog_fd < 0)
                return;

        if (disarm) {
                (void) watchdog_set_enable(false);

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
}
