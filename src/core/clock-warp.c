/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/time.h>

#include "sd-messages.h"

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
                timesyncd_usec = timespec_load(&st.st_mtim);
        else if (r != -ENOENT)
                log_warning_errno(r, "Could not stat %s, ignoring: %m", TIMESYNCD_CLOCK_FILE);

        r = RET_NERRNO(stat(EPOCH_CLOCK_FILE, &st));
        if (r >= 0)
                epoch_usec = timespec_load(&st.st_mtim);
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
        if (r < 0) {
                if (advance)
                        return (void) log_error_errno(r, "Current system time is before epoch, but cannot correct: %m");
                else
                        return (void) log_error_errno(r, "Current system time is further ahead than %s after epoch, but cannot correct: %m",
                                                      FORMAT_TIMESPAN(CLOCK_VALID_RANGE_USEC_MAX, USEC_PER_DAY));
        }

        const char *from =
                epoch_usec == (usec_t) TIME_EPOCH * USEC_PER_SEC ? "built-in epoch" :
                epoch_usec == timesyncd_usec ? "timestamp on "TIMESYNCD_CLOCK_FILE :
                "timestamp on "EPOCH_CLOCK_FILE;
        if (advance)
                log_struct(LOG_INFO,
                           "MESSAGE_ID=" SD_MESSAGE_TIME_BUMP_STR,
                           "REALTIME_USEC=" USEC_FMT, epoch_usec,
                           "DIRECTION=forwards",
                           LOG_MESSAGE("System time advanced to %s: %s",
                                       from,
                                       FORMAT_TIMESTAMP(epoch_usec)));
        else
                log_struct(LOG_INFO,
                           "MESSAGE_ID=" SD_MESSAGE_TIME_BUMP_STR,
                           "REALTIME_USEC=" USEC_FMT, epoch_usec,
                           "DIRECTION=backwards",
                           LOG_MESSAGE("System time was further ahead than %s after %s, clock reset to %s",
                                       FORMAT_TIMESPAN(CLOCK_VALID_RANGE_USEC_MAX, USEC_PER_DAY),
                                       from,
                                       FORMAT_TIMESTAMP(epoch_usec)));
}
