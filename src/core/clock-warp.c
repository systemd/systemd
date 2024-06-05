/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/time.h>

#include "clock-util.h"
#include "clock-warp.h"
#include "errno-util.h"

int clock_reset_timewarp(void) {
        static const struct timezone tz = {
                .tz_minuteswest = 0,
                .tz_dsttime = 0, /* DST_NONE */
        };

        /* The very first call to settimeofday() does time warp magic. Do a dummy call here, so the time
         * warping is sealed and all later calls behave as expected. */
        return RET_NERRNO(settimeofday(NULL, &tz));
}

void clock_apply_epoch(bool allow_backwards) {
        usec_t epoch_usec = 0, timesyncd_usec = 0;
        struct stat st;
        int r;

        r = RET_NERRNO(stat(TIMESYNCD_CLOCK_FILE, &st));
        if (r >= 0)
                epoch_usec = timespec_load(&st.st_mtim);
        else if (r != -ENOENT)
                log_warning_errno(r, "Could not stat %s, ignoring: %m", TIMESYNCD_CLOCK_FILE);

        r = RET_NERRNO(stat(EPOCH_CLOCK_FILE, &st));
        if (r >= 0)
                timesyncd_usec = timespec_load(&st.st_mtim);
        else if (r != -ENOENT)
                log_warning_errno(r, "Could not stat %s, ignoring: %m", EPOCH_CLOCK_FILE);

        epoch_usec = MAX3(epoch_usec,
                          timesyncd_usec,
                          (usec_t) TIME_EPOCH * USEC_PER_SEC);

        if (epoch_usec == 0)  /* Weird, but may happen if mtimes were reset to 0 during compilation. */
                return log_debug("Clock epoch is 0, skipping clock adjustment.");

        usec_t now_usec = now(CLOCK_REALTIME);
        bool advance;

        if (now_usec < epoch_usec)
                advance = true;
        else if (CLOCK_VALID_RANGE_USEC_MAX > 0 &&
                 now_usec > usec_add(epoch_usec, CLOCK_VALID_RANGE_USEC_MAX) &&
                 allow_backwards)
                advance = false;
        else
                return;  /* Nothing to do. */

        r = RET_NERRNO(clock_settime(CLOCK_REALTIME, TIMESPEC_STORE(epoch_usec)));
        if (r < 0 && advance)
                return (void) log_error_errno(r, "Current system time is before build time, but cannot correct: %m");
        else if (r < 0)
                return (void) log_error_errno(r, "Current system time is further ahead than %s after build time, but cannot correct: %m",
                                              FORMAT_TIMESPAN(CLOCK_VALID_RANGE_USEC_MAX, USEC_PER_DAY));
        else if (advance)
                log_info("System time was before build time, advanced clock.");
        else
                log_info("System time was further ahead than %s after build time, reset clock to build time.",
                         FORMAT_TIMESPAN(CLOCK_VALID_RANGE_USEC_MAX, USEC_PER_DAY));
}
