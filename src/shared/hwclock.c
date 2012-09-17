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
#include "hwclock.h"

static int rtc_open(int flags) {
        int fd;
        DIR *d;

        /* First, we try to make use of the /dev/rtc symlink. If that
         * doesn't exist, we open the first RTC which has hctosys=1
         * set. If we don't find any we just take the first RTC that
         * exists at all. */

        fd = open("/dev/rtc", flags);
        if (fd >= 0)
                return fd;

        d = opendir("/sys/class/rtc");
        if (!d)
                goto fallback;

        for (;;) {
                char *p, *v;
                struct dirent buf, *de;
                int r;

                r = readdir_r(d, &buf, &de);
                if (r != 0)
                        goto fallback;

                if (!de)
                        goto fallback;

                if (ignore_file(de->d_name))
                        continue;

                p = strjoin("/sys/class/rtc/", de->d_name, "/hctosys", NULL);
                if (!p) {
                        closedir(d);
                        return -ENOMEM;
                }

                r = read_one_line_file(p, &v);
                free(p);

                if (r < 0)
                        continue;

                r = parse_boolean(v);
                free(v);

                if (r <= 0)
                        continue;

                p = strappend("/dev/", de->d_name);
                fd = open(p, flags);
                free(p);

                if (fd >= 0) {
                        closedir(d);
                        return fd;
                }
        }

fallback:
        if (d)
                closedir(d);

        fd = open("/dev/rtc0", flags);
        if (fd < 0)
                return -errno;

        return fd;
}

int hwclock_get_time(struct tm *tm) {
        int fd;
        int err = 0;

        assert(tm);

        fd = rtc_open(O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        /* This leaves the timezone fields of struct tm
         * uninitialized! */
        if (ioctl(fd, RTC_RD_TIME, tm) < 0)
                err = -errno;

        /* We don't know daylight saving, so we reset this in order not
         * to confused mktime(). */
        tm->tm_isdst = -1;

        close_nointr_nofail(fd);

        return err;
}

int hwclock_set_time(const struct tm *tm) {
        int fd;
        int err = 0;

        assert(tm);

        fd = rtc_open(O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, RTC_SET_TIME, tm) < 0)
                err = -errno;

        close_nointr_nofail(fd);

        return err;
}
int hwclock_is_localtime(void) {
        FILE *f;
        bool local = false;

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

                fclose(f);

                if (!b)
                        return -EIO;

                truncate_nl(line);
                local = streq(line, "LOCAL");

        } else if (errno != -ENOENT)
                return -errno;

        return local;
}

int hwclock_set_timezone(int *min) {
        const struct timeval *tv_null = NULL;
        struct timespec ts;
        struct tm *tm;
        int minuteswest;
        struct timezone tz;

        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);
        assert_se(tm = localtime(&ts.tv_sec));
        minuteswest = tm->tm_gmtoff / 60;

        tz.tz_minuteswest = -minuteswest;
        tz.tz_dsttime = 0; /* DST_NONE*/

        /*
         * If the hardware clock does not run in UTC, but in local time:
         * The very first time we set the kernel's timezone, it will warp
         * the clock so that it runs in UTC instead of local time.
         */
        if (settimeofday(tv_null, &tz) < 0)
                return -errno;
        if (min)
                *min = minuteswest;
        return 0;
}

int hwclock_reset_timezone(void) {
        const struct timeval *tv_null = NULL;
        struct timezone tz;

        tz.tz_minuteswest = 0;
        tz.tz_dsttime = 0; /* DST_NONE*/

        /*
         * The very first time we set the kernel's timezone, it will warp
         * the clock. Do a dummy call here, so the time warping is sealed
         * and we set only the time zone with next call.
         */
        if (settimeofday(tv_null, &tz) < 0)
                return -errno;

        return 0;
}
