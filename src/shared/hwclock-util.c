/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/rtc.h>
#include <sys/ioctl.h>
#include <time.h>

#include "errno-util.h"
#include "fd-util.h"
#include "hwclock-util.h"

int hwclock_get(const char *rtc_device, struct tm *tm /* input + output! */) {
        _cleanup_close_ int fd = -EBADF;
        struct tm t = {};

        if (!rtc_device)
                rtc_device = "/dev/rtc";

        fd = open(rtc_device, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (tm)
                t = *tm;

        /* This leaves the timezone fields of struct ret uninitialized! */
        if (ioctl(fd, RTC_RD_TIME, &t) < 0)
                /* Some drivers return -EINVAL in case the time could not be kept, i.e. power loss
                 * happened. Let's turn that into a clearly recognizable error */
                return errno == EINVAL ? -ENODATA : -errno;

        if (tm) {
                /* We don't know daylight saving, so we reset this in order not to confuse mktime(). */
                t.tm_isdst = -1;
                *tm = t;
        }

        return 0;
}

int hwclock_set(const char *rtc_device, const struct tm *tm) {
        _cleanup_close_ int fd = -EBADF;

        assert(tm);

        if (!rtc_device)
                rtc_device = "/dev/rtc";

        fd = open(rtc_device, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return RET_NERRNO(ioctl(fd, RTC_SET_TIME, tm));
}
