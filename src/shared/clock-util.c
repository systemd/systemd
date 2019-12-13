/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <time.h>
#include <linux/rtc.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "alloc-util.h"
#include "clock-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "string-util.h"

int clock_get_hwclock(struct tm *tm) {
        _cleanup_close_ int fd = -1;

        assert(tm);

        fd = open("/dev/rtc", O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        /* This leaves the timezone fields of struct tm
         * uninitialized! */
        if (ioctl(fd, RTC_RD_TIME, tm) < 0)
                return -errno;

        /* We don't know daylight saving, so we reset this in order not
         * to confuse mktime(). */
        tm->tm_isdst = -1;

        return 0;
}

int clock_set_hwclock(const struct tm *tm) {
        _cleanup_close_ int fd = -1;

        assert(tm);

        fd = open("/dev/rtc", O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, RTC_SET_TIME, tm) < 0)
                return -errno;

        return 0;
}

int clock_is_localtime(const char* adjtime_path) {
        _cleanup_fclose_ FILE *f;
        int r;

        if (!adjtime_path)
                adjtime_path = "/etc/adjtime";

        /*
         * The third line of adjtime is "UTC" or "LOCAL" or nothing.
         *   # /etc/adjtime
         *   0.0 0 0
         *   0
         *   UTC
         */
        f = fopen(adjtime_path, "re");
        if (f) {
                _cleanup_free_ char *line = NULL;
                unsigned i;

                for (i = 0; i < 2; i++) { /* skip the first two lines */
                        r = read_line(f, LONG_LINE_MAX, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return false; /* less than three lines → default to UTC */
                }

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return false; /* less than three lines → default to UTC */

                return streq(line, "LOCAL");

        } else if (errno != ENOENT)
                return -errno;

        /* adjtime not present → default to UTC */
        return false;
}

int clock_set_timezone(int *min) {
        const struct timeval *tv_null = NULL;
        struct timespec ts;
        struct tm tm;
        int minutesdelta;
        struct timezone tz;

        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);
        assert_se(localtime_r(&ts.tv_sec, &tm));
        minutesdelta = tm.tm_gmtoff / 60;

        tz.tz_minuteswest = -minutesdelta;
        tz.tz_dsttime = 0; /* DST_NONE */

        /*
         * If the RTC does not run in UTC but in local time, the very first
         * call to settimeofday() will set the kernel's timezone and will warp the
         * system clock, so that it runs in UTC instead of the local time we
         * have read from the RTC.
         */
        if (settimeofday(tv_null, &tz) < 0)
                return negative_errno();

        if (min)
                *min = minutesdelta;
        return 0;
}

int clock_reset_timewarp(void) {
        const struct timeval *tv_null = NULL;
        struct timezone tz;

        tz.tz_minuteswest = 0;
        tz.tz_dsttime = 0; /* DST_NONE */

        /*
         * The very first call to settimeofday() does time warp magic. Do a
         * dummy call here, so the time warping is sealed and all later calls
         * behave as expected.
         */
        if (settimeofday(tv_null, &tz) < 0)
                return -errno;

        return 0;
}

#define TIME_EPOCH_USEC ((usec_t) TIME_EPOCH * USEC_PER_SEC)

int clock_apply_epoch(void) {
        struct timespec ts;

        if (now(CLOCK_REALTIME) >= TIME_EPOCH_USEC)
                return 0;

        if (clock_settime(CLOCK_REALTIME, timespec_store(&ts, TIME_EPOCH_USEC)) < 0)
                return -errno;

        return 1;
}
