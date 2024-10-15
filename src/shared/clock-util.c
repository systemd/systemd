/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

int clock_is_localtime(const char *adjtime_path) {
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
        _cleanup_fclose_ FILE *f = fopen(adjtime_path, "re");
        if (!f) {
                if (errno != ENOENT)
                        return -errno;

                /* adjtime_path not present → default to UTC */
                return false;
        }

        _cleanup_free_ char *line = NULL;
        for (unsigned i = 0; i < 2; i++) { /* skip the first two lines */
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
}

int clock_set_timezone(int *ret_minutesdelta) {
        struct tm tm;
        int r;

        r = localtime_or_gmtime_usec(now(CLOCK_REALTIME), /* utc= */ false, &tm);
        if (r < 0)
                return r;

        int minutesdelta = tm.tm_gmtoff / 60;

        struct timezone tz = {
                .tz_minuteswest = -minutesdelta,
                .tz_dsttime = 0, /* DST_NONE */
        };

        /* If the RTC does not run in UTC but in local time, the very first call to settimeofday() will set
         * the kernel's timezone and will warp the system clock, so that it runs in UTC instead of the local
         * time we have read from the RTC. */
        if (settimeofday(NULL, &tz) < 0)
                return -errno;

        if (ret_minutesdelta)
                *ret_minutesdelta = minutesdelta;

        return 0;
}
