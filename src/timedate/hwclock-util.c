/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/rtc.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "errno-util.h"
#include "fd-util.h"
#include "hwclock-util.h"

int hwclock_get(struct tm *tm /* input + output! */) {
        _cleanup_close_ int fd = -EBADF;

        assert(tm);

        fd = open("/dev/rtc", O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        /* This leaves the timezone fields of struct ret uninitialized! */
        if (ioctl(fd, RTC_RD_TIME, tm) < 0)
                /* Some drivers return -EINVAL in case the time could not be kept, i.e. power loss
                 * happened. Let's turn that into a clearly recognizable error */
                return errno == EINVAL ? -ENODATA : -errno;

        /* We don't know daylight saving, so we reset this in order not to confuse mktime(). */
        tm->tm_isdst = -1;

        return 0;
}

int hwclock_set(const struct tm *tm) {
        _cleanup_close_ int fd = -EBADF;

        assert(tm);

        fd = open("/dev/rtc", O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return RET_NERRNO(ioctl(fd, RTC_SET_TIME, tm));
}
