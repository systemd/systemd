/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <linux/rtc.h>

#include "macro.h"
#include "util.h"
#include "log.h"
#include "strv.h"
#include "clock-util.h"
#include "fileio.h"

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

int clock_is_localtime(void) {
        _cleanup_fclose_ FILE *f;

        /*
         * The third line of adjtime is "UTC" or "LOCAL" or nothing.
         *   # /etc/adjtime
         *   0.0 0 0
         *   0
         *   UTC
         */
        f = fopen("/etc/adjtime", "re");
        if (f) {
                char line[LINE_MAX];
                bool b;

                b = fgets(line, sizeof(line), f) &&
                        fgets(line, sizeof(line), f) &&
                        fgets(line, sizeof(line), f);
                if (!b)
                        return -EIO;

                truncate_nl(line);
                return streq(line, "LOCAL");

        } else if (errno != ENOENT)
                return -errno;

        return 0;
}

int clock_set_timezone(int *min) {
        const struct timeval *tv_null = NULL;
        struct timespec ts;
        struct tm *tm;
        int minutesdelta;
        struct timezone tz;

        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);
        assert_se(tm = localtime(&ts.tv_sec));
        minutesdelta = tm->tm_gmtoff / 60;

        tz.tz_minuteswest = -minutesdelta;
        tz.tz_dsttime = 0; /* DST_NONE*/

        /*
         * If the hardware clock does not run in UTC, but in local time:
         * The very first time we set the kernel's timezone, it will warp
         * the clock so that it runs in UTC instead of local time.
         */
        if (settimeofday(tv_null, &tz) < 0)
                return -errno;
        if (min)
                *min = minutesdelta;
        return 0;
}

int clock_reset_timezone(void) {
        const struct timeval *tv_null = NULL;
        struct timezone tz;

        tz.tz_minuteswest = 0;
        tz.tz_dsttime = 0; /* DST_NONE*/

        /*
         * The very first time we set the kernel's timezone, it will warp
         * the clock. Do a dummy call here, so the time warping is sealed
         * and we set only the timezone with the next call.
         */
        if (settimeofday(tv_null, &tz) < 0)
                return -errno;

        return 0;
}
