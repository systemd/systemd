/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/watchdog.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "path-util.h"
#include "ratelimit.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "watchdog.h"

static int watchdog_fd = -EBADF;
static char *watchdog_device = NULL;
static usec_t watchdog_timeout = 0; /* 0 → close device and USEC_INFINITY → don't change timeout */
static usec_t watchdog_pretimeout = 0; /* 0 → disable pretimeout and USEC_INFINITY → don't change pretimeout */
static usec_t watchdog_last_good_ping = USEC_INFINITY;
static usec_t watchdog_last_bad_ping = USEC_INFINITY;
static unsigned watchdog_bad_pings = 0;
static bool watchdog_supports_pretimeout = false; /* Depends on kernel state that might change at runtime */
static char *watchdog_pretimeout_governor = NULL;

/* Starting from kernel version 4.5, the maximum allowable watchdog timeout is
 * UINT_MAX/1000U seconds (since internal calculations are done in milliseconds
 * using unsigned integers. However, the kernel's userspace API for the watchdog
 * uses signed integers for its ioctl parameters (even for timeout values and
 * bit flags) so this is why we must consider the maximum signed integer value
 * as well.
 */
#define WATCHDOG_TIMEOUT_MAX_SEC (CONST_MIN(UINT_MAX/1000U, (unsigned)INT_MAX))

/* How many times to ping the watchdog in a single burst. */
#define WATCHDOG_PING_BURST 3
/* How many times to ping the watchdog in total before giving up on it. */
#define WATCHDOG_MAX_FAILED_PINGS 15

#define WATCHDOG_GOV_NAME_MAXLEN 20 /* From the kernel watchdog driver */

static int saturated_usec_to_sec(usec_t val) {
        usec_t t = DIV_ROUND_UP(val, USEC_PER_SEC);
        return MIN(t, (usec_t) WATCHDOG_TIMEOUT_MAX_SEC); /* Saturate to watchdog max */
}

static int watchdog_get_sysfs_path(const char *filename, char **ret_path) {
        struct stat st;

        if (watchdog_fd < 0)
                return -EBADF;

        if (fstat(watchdog_fd, &st))
                return -errno;

        if (!S_ISCHR(st.st_mode))
                return -EBADF;

        if (asprintf(ret_path, "/sys/dev/char/"DEVNUM_FORMAT_STR"/%s", DEVNUM_FORMAT_VAL(st.st_rdev), filename) < 0)
                return -ENOMEM;

        return 0;
}

static int watchdog_get_pretimeout_governor(char **ret_gov) {
        _cleanup_free_ char *sys_fn = NULL;
        int r;

        r = watchdog_get_sysfs_path("pretimeout_governor", &sys_fn);
        if (r < 0)
                return r;

        log_info("Watchdog: reading from %s", sys_fn);

        r = read_virtual_file(sys_fn, WATCHDOG_GOV_NAME_MAXLEN - 1, ret_gov, NULL);
        if (r < 0)
                return r;

        delete_trailing_chars(*ret_gov, WHITESPACE);

        return 0;
}

static int watchdog_set_pretimeout_governor(const char *governor) {
        _cleanup_free_ char *sys_fn = NULL;
        int r;

        if (isempty(governor))
                return 0; /* Nothing to do */

        r = watchdog_get_sysfs_path("pretimeout_governor", &sys_fn);
        if (r < 0)
                return r;

        log_info("Watchdog: setting pretimeout_governor to '%s' via '%s'", governor, sys_fn);

        r = write_string_file(sys_fn,
                              governor,
                              WRITE_STRING_FILE_DISABLE_BUFFER | WRITE_STRING_FILE_VERIFY_ON_FAILURE | WRITE_STRING_FILE_VERIFY_IGNORE_NEWLINE);
        if (r < 0)
                return log_error_errno(r, "Failed to set watchdog pretimeout_governor to '%s': %m", governor);

        return r;
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

static int watchdog_read_timeout(void) {
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

static int watchdog_read_pretimeout(void) {
        int sec = 0;

        assert(watchdog_fd >= 0);

        if (ioctl(watchdog_fd, WDIOC_GETPRETIMEOUT, &sec) < 0) {
                watchdog_pretimeout = 0;
                return log_full_errno(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_DEBUG : LOG_WARNING, errno, "Failed to get watchdog pretimeout value, ignoring: %m");
        }

        watchdog_pretimeout = sec * USEC_PER_SEC;

        return 0;
}

static int watchdog_set_pretimeout(void) {
        int sec;

        assert(watchdog_fd >= 0);
        assert(watchdog_pretimeout != USEC_INFINITY);

        sec = saturated_usec_to_sec(watchdog_pretimeout);

        if (ioctl(watchdog_fd, WDIOC_SETPRETIMEOUT, &sec) < 0) {
                watchdog_pretimeout = 0;

                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        log_info("Watchdog does not support pretimeouts.");
                        return 0;
                }

                return log_error_errno(errno, "Failed to set watchdog pretimeout to %s: %m", FORMAT_TIMESPAN(sec, USEC_PER_SEC));
        }

        /* The set ioctl does not return the actual value set so get it now. */
        (void) watchdog_read_pretimeout();

        return 0;
}

usec_t watchdog_get_last_ping(clockid_t clock) {
        return map_clock_usec(watchdog_last_good_ping, CLOCK_BOOTTIME, clock);
}

dual_timestamp* watchdog_get_last_ping_as_dual_timestamp(dual_timestamp *ret) {
        assert(ret);

        ret->monotonic = watchdog_get_last_ping(CLOCK_MONOTONIC);
        ret->realtime = watchdog_get_last_ping(CLOCK_REALTIME);

        return ret;
}

static int watchdog_ping_now(void) {
        int r;

        assert(watchdog_fd >= 0);

        r = RET_NERRNO(ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0));
        if (r < 0) {
                watchdog_last_bad_ping = now(CLOCK_BOOTTIME);
                if (++ watchdog_bad_pings >= WATCHDOG_MAX_FAILED_PINGS) {
                        log_struct_errno(LOG_ERR, r,
                                         LOG_MESSAGE("Failed to ping hardware watchdog %s, closing watchdog after %u attempts: %m",
                                                     watchdog_device, watchdog_bad_pings),
                                         "MESSAGE_ID=" SD_MESSAGE_WATCHDOG_PING_FAILED_STR,
                                         "WATCHDOG_DEVICE=%s", watchdog_device);
                        watchdog_timeout = USEC_INFINITY;
                        watchdog_close(/* disarm= */ true);
                } else
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_MESSAGE("Failed to ping hardware watchdog %s: %m",
                                                     watchdog_device),
                                         "MESSAGE_ID=" SD_MESSAGE_WATCHDOG_PING_FAILED_STR,
                                         "WATCHDOG_DEVICE=%s", watchdog_device);
        } else {
                watchdog_last_good_ping = now(CLOCK_BOOTTIME);
                if (watchdog_bad_pings > 0) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("Successfully pinged hardware watchdog %s after %u attempts: %m",
                                               watchdog_device, watchdog_bad_pings + 1),
                                   "WATCHDOG_DEVICE=%s", watchdog_device);
                        watchdog_bad_pings = 0;
                        watchdog_last_bad_ping = USEC_INFINITY;
                }
        }

        return r;
}

static int watchdog_update_pretimeout(void) {
        _cleanup_free_ char *governor = NULL;
        int r, t_sec, pt_sec;

        if (watchdog_fd < 0)
                return 0;

        if (watchdog_timeout == USEC_INFINITY || watchdog_pretimeout == USEC_INFINITY)
                return 0;

        if (!watchdog_supports_pretimeout && watchdog_pretimeout == 0)
                return 0; /* Nothing to do */

        /* The configuration changed, do not assume it can still work, as the module(s)
         * might have been unloaded. */
        watchdog_supports_pretimeout = false;

        /* Update the pretimeout governor as well */
        (void) watchdog_set_pretimeout_governor(watchdog_pretimeout_governor);

        r = watchdog_get_pretimeout_governor(&governor);
        if (r < 0)
                return log_warning_errno(r, "Watchdog: failed to read pretimeout governor: %m");
        if (isempty(governor))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Watchdog: no pretimeout governor detected - is the required kernel module loaded?");

        /* If we have a pretimeout governor, then pretimeout is supported. Without a governor
         * pretimeout does not work at all.
         * Note that this might require a kernel module that is not autoloaded, so we don't
         * cache this, but we check every time the configuration changes. */
        watchdog_supports_pretimeout = true;

        /* Determine if the pretimeout is valid for the current watchdog timeout. */
        t_sec = saturated_usec_to_sec(watchdog_timeout);
        pt_sec = saturated_usec_to_sec(watchdog_pretimeout);
        if (pt_sec >= t_sec) {
                r = log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                    "Cannot set watchdog pretimeout to %is (%s watchdog timeout of %is)",
                                    pt_sec, pt_sec == t_sec ? "same as" : "longer than", t_sec);
                (void) watchdog_read_pretimeout();
        } else
                r = watchdog_set_pretimeout();

        if (watchdog_pretimeout == 0)
                log_info("Watchdog pretimeout is disabled.");
        else
                log_info("Watchdog running with a pretimeout of %s with governor '%s'.",
                         FORMAT_TIMESPAN(watchdog_pretimeout, 0),
                         governor);

        return r;
}

static int watchdog_update_timeout(void) {
        int r;
        usec_t previous_timeout;

        assert(watchdog_timeout > 0);

        if (watchdog_fd < 0)
                return 0;

        previous_timeout = watchdog_timeout;

        if (watchdog_timeout != USEC_INFINITY) {
                r = watchdog_set_timeout();
                if (r < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(r))
                                return log_error_errno(r, "Failed to set watchdog hardware timeout to %s: %m",
                                                       FORMAT_TIMESPAN(watchdog_timeout, 0));

                        log_info("Modifying watchdog hardware timeout is not supported, reusing the programmed timeout.");
                        watchdog_timeout = USEC_INFINITY;
                }
        }

        if (watchdog_timeout == USEC_INFINITY) {
                r = watchdog_read_timeout();
                if (r < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(r))
                                return log_error_errno(r, "Failed to query watchdog hardware timeout: %m");
                        log_info("Reading watchdog hardware timeout is not supported, reusing the configured timeout.");
                        watchdog_timeout = previous_timeout;
                }
        }

        /* If the watchdog timeout was changed, the pretimeout could have been
         * changed as well by the driver or the kernel so we need to update the
         * pretimeout now. Or if the watchdog is being configured for the first
         * time, we want to configure the pretimeout before it is enabled. */
        (void) watchdog_update_pretimeout();

        r = watchdog_set_enable(true);
        if (r < 0)
                return r;

        log_info("Watchdog running with a hardware timeout of %s.", FORMAT_TIMESPAN(watchdog_timeout, 0));

        return watchdog_ping_now();
}

static int watchdog_open(bool ignore_ratelimit) {
        static RateLimit watchdog_open_ratelimit = { 0, 1 }; /* The interval is initialized dynamically below. */
        struct watchdog_info ident;
        char **try_order;
        int r;

        assert(watchdog_fd < 0);
        assert(watchdog_timeout > 0);

        watchdog_open_ratelimit.interval = MIN(watchdog_timeout / 2, 5 * USEC_PER_SEC);

        if (!ratelimit_below(&watchdog_open_ratelimit))
                if (!ignore_ratelimit)  /* If ignore_ratelimit, we update the timestamp, but continue. */
                        return -EWOULDBLOCK;

        /* Let's prefer new-style /dev/watchdog0 (i.e. kernel 3.5+) over classic /dev/watchdog. The former
         * has the benefit that we can easily find the matching directory in sysfs from it, as the relevant
         * sysfs attributes can only be found via /sys/dev/char/<major>:<minor> if the new-style device
         * major/minor is used, not the old-style. */
        try_order = !watchdog_device || PATH_IN_SET(watchdog_device, "/dev/watchdog", "/dev/watchdog0") ?
                STRV_MAKE("/dev/watchdog0", "/dev/watchdog") : STRV_MAKE(watchdog_device);

        STRV_FOREACH(wd, try_order) {
                watchdog_fd = RET_NERRNO(open(*wd, O_WRONLY|O_CLOEXEC));
                if (watchdog_fd >= 0) {
                        if (free_and_strdup(&watchdog_device, *wd) < 0) {
                                r = log_oom_debug();
                                goto close_and_fail;
                        }

                        break;
                }

                if (watchdog_fd != -ENOENT)
                        return log_struct_errno(LOG_WARNING, watchdog_fd,
                                                LOG_MESSAGE("Failed to open watchdog device %s: %m", *wd),
                                                "MESSAGE_ID=" SD_MESSAGE_WATCHDOG_OPEN_FAILED_STR,
                                                "WATCHDOG_DEVICE=%s", *wd);
        }

        if (watchdog_fd < 0)
                return log_debug_errno(watchdog_fd, "Failed to open %swatchdog device%s%s.",
                                       watchdog_device ? "" : "any ",
                                       watchdog_device ? " " : "",
                                       strempty(watchdog_device));

        watchdog_last_good_ping = watchdog_last_bad_ping = USEC_INFINITY;
        watchdog_bad_pings = 0;

        r = RET_NERRNO(ioctl(watchdog_fd, WDIOC_GETSUPPORT, &ident));
        if (r < 0)
                log_struct_errno(LOG_INFO, r,
                                 LOG_MESSAGE("Using hardware watchdog %s, no support for WDIOC_GETSUPPORT ioctl: %m",
                                             watchdog_device),
                                 "MESSAGE_ID=" SD_MESSAGE_WATCHDOG_OPENED_STR,
                                 "WATCHDOG_DEVICE=%s", watchdog_device);
        else
                log_struct(LOG_INFO,
                           LOG_MESSAGE("Using hardware watchdog %s: '%s', version %x.",
                                       watchdog_device,
                                       ident.identity,
                                       ident.firmware_version),
                           "MESSAGE_ID=" SD_MESSAGE_WATCHDOG_OPENED_STR,
                           "WATCHDOG_DEVICE=%s", watchdog_device);

        r = watchdog_update_timeout();
        if (r < 0)
                goto close_and_fail;

        return 0;

close_and_fail:
        watchdog_close(/* disarm= */ true);
        return r;
}

const char* watchdog_get_device(void) {
        return watchdog_device;
}

int watchdog_set_device(const char *path) {
        int r;

        r = free_and_strdup(&watchdog_device, path);
        if (r > 0) /* watchdog_device changed */
                watchdog_close(/* disarm= */ true);

        return r;
}

int watchdog_setup(usec_t timeout) {
        usec_t previous_timeout;
        int r;

        /* timeout=0 closes the device whereas passing timeout=USEC_INFINITY opens it (if needed)
         * without configuring any particular timeout and thus reuses the programmed value (therefore
         * it's a nop if the device is already opened). */

        if (timeout == 0) {
                watchdog_close(/* disarm= */ true);
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
                return watchdog_open(/* ignore_ratelimit= */ false);

        r = watchdog_update_timeout();
        if (r < 0)
                watchdog_timeout = previous_timeout;

        return r;
}

int watchdog_setup_pretimeout(usec_t timeout) {
        /* timeout=0 disables the pretimeout whereas timeout=USEC_INFINITY is a nop. */
        if ((watchdog_fd >= 0 && timeout == watchdog_pretimeout) || timeout == USEC_INFINITY)
                return 0;

        /* Initialize the watchdog timeout with the caller value. This value is
         * going to be updated by update_pretimeout() with the running value,
         * even if it fails to update the timeout. */
        watchdog_pretimeout = timeout;

        return watchdog_update_pretimeout();
}

int watchdog_setup_pretimeout_governor(const char *governor) {
        if (free_and_strdup(&watchdog_pretimeout_governor, governor) < 0)
                return -ENOMEM;

        return watchdog_set_pretimeout_governor(watchdog_pretimeout_governor);
}

static usec_t watchdog_calc_timeout(void) {
        /* If we failed to many times, don't schedule the next attempt at all. */
        if (watchdog_bad_pings >= WATCHDOG_MAX_FAILED_PINGS)
                return 0;

        /* Calculate the effective timeout which accounts for the watchdog
         * pretimeout if configured and supported. */
        if (watchdog_supports_pretimeout && timestamp_is_set(watchdog_pretimeout) && watchdog_timeout >= watchdog_pretimeout)
                return watchdog_timeout - watchdog_pretimeout;
        else
                return watchdog_timeout;
}

usec_t watchdog_runtime_wait(unsigned divisor) {
        usec_t timeout = watchdog_calc_timeout();
        if (!timestamp_is_set(timeout))
                return USEC_INFINITY;

        /* Sleep watchdog timeout / divisor since the last successful ping attempt at most,
         * or the fifth of that if the ping failed. */

        usec_t ts = MAX(timestamp_is_set(watchdog_last_good_ping) ? watchdog_last_good_ping : 0u,
                        timestamp_is_set(watchdog_last_bad_ping) ? watchdog_last_bad_ping : 0u);
        if (ts > 0) {
                usec_t ntime = now(CLOCK_BOOTTIME);
                if (ts == watchdog_last_bad_ping)
                        divisor *= 5;

                assert(ntime >= ts);
                return usec_sub_unsigned(ts + timeout / divisor, ntime);
        }

        return timeout / divisor;
}

int watchdog_ping(void) {
        if (watchdog_timeout == 0)
                return 0;

        if (watchdog_fd < 0)
                /* open_watchdog() will automatically ping the device for us if necessary */
                return watchdog_open(/* ignore_ratelimit= */ false);

        /* Ping approximately watchdog_timeout/4 after a successful ping, or even less than that
         * after an unsuccessful ping. */
        if (watchdog_runtime_wait(/* divisor= */ 4) > 0)
                return 0;

        return watchdog_ping_now();
}

void watchdog_report_if_missing(void) {
        /* If we failed to open the watchdog because the device doesn't exist, report why. If we successfully
         * opened a device, or opening failed for a different reason, we logged then. But ENOENT failure may
         * be transient, for example because modules being loaded or the hardware being detected. This
         * function can be called to log after things have settled down.
         *
         * If a device was specified explicitly, raise level. */

        if (watchdog_fd != -ENOENT)
                return;

        /* We attempt to open the watchdog one last time here, so that if we log, we log accurately. */
        if (watchdog_open(/* ignore_ratelimit= */ true) >= 0)
                return;

        if (watchdog_device)
                log_struct_errno(LOG_WARNING, watchdog_fd,
                                 LOG_MESSAGE("Failed to open watchdog device %s before the initial transaction completed: %m",
                                             watchdog_device),
                                 "MESSAGE_ID=" SD_MESSAGE_WATCHDOG_OPEN_FAILED_STR,
                                 "WATCHDOG_DEVICE=%s", watchdog_device);
        else
                log_struct_errno(LOG_WARNING, watchdog_fd,
                                 LOG_MESSAGE("Failed to open any watchdog device before the initial transaction completed: %m"),
                                 "MESSAGE_ID=" SD_MESSAGE_WATCHDOG_OPEN_FAILED_STR);
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
