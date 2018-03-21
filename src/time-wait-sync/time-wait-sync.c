/*
 * systemd service to wait until kernel realtime clock is synchronized
 *
 * Copyright 2018 Peter A. Bigot
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <unistd.h>

#include "sd-event.h"

#include "fd-util.h"
#include "missing.h"
#include "signal-util.h"
#include "time-util.h"

typedef struct ClockState {
        int fd;                        /* non-negative is descriptor from timerfd_create */
        int adjtime_state;             /* return value from last adjtimex(2) call */
        sd_event_source *event_source; /* non-null is the active io event source */
} ClockState;

static void clock_state_release(ClockState *sp) {
        sp->event_source = sd_event_source_unref(sp->event_source);
        sp->fd = safe_close(sp->fd);
}

static int clock_state_update(ClockState *sp,
                              sd_event *event);

static int io_handler(sd_event_source * s,
                      int fd,
                      uint32_t revents,
                      void *userdata) {
        ClockState *sp = userdata;

        return clock_state_update(sp, sd_event_source_get_event(s));
}

static int clock_state_update(ClockState *sp,
                              sd_event *event) {
        static const struct itimerspec its = {
                .it_value.tv_sec = TIME_T_MAX,
        };
        int r;
        struct timex tx = {};
        char buf[MAX((size_t)FORMAT_TIMESTAMP_MAX, STRLEN("unrepresentable"))];
        usec_t t;
        const char * ts;

        clock_state_release(sp);

        /* The kernel supports cancelling timers whenever its realtime clock is "set" (which can happen in a variety of
         * ways, generally adjustments of at least 500 ms).  The way this module works is we set up a timer that will
         * wake when it the clock is set, and when that happens we read the clock synchronization state from the return
         * value of adjtimex(2), which supports the NTP time adjustment protocol.
         *
         * The kernel determines whether the clock is synchronized using driver-specific tests, based on time
         * information passed by an application, generally through adjtimex(2).  If the application asserts the clock
         * is synchronized, but does not also do something that "sets the clock", the timer will not be cancelled and
         * synchronization will not be detected.  Should this behavior be observed with a time synchronization provider
         * this code might be reworked to do a periodic check as well.
         *
         * Similarly, this service will never complete if the application sets the time without also providing
         * information that adjtimex(2) can use to determine that the clock is synchronized.
         *
         * Well-behaved implementations including systemd-timesyncd should not produce either situation.  For timesyncd
         * the initial set of the timestamp uses settimeofday(2), which sets the clock but does not mark it
         * synchronized.  When an NTP source is selected it sets the clock again with clock_adjtime(2) which does mark
         * it synchronized. */
        r = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
        if (r < 0) {
                log_error_errno(errno, "Failed to create timerfd: %m");
                goto finish;
        }
        sp->fd = r;

        r = timerfd_settime(sp->fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &its, NULL);
        if (r < 0) {
                log_error_errno(errno, "Failed to set timerfd conditions: %m");
                goto finish;
        }

        r = adjtimex(&tx);
        if (r < 0) {
                log_error_errno(errno, "Failed to read adjtimex state: %m");
                goto finish;
        }
        sp->adjtime_state = r;

        if (tx.status & STA_NANO)
                tx.time.tv_usec /= 1000;
        t = timeval_load(&tx.time);
        ts = format_timestamp_us_utc(buf, sizeof(buf), t);
        if (!ts)
                strcpy(buf, "unrepresentable");
        log_info("adjtime state %d status %x time %s", sp->adjtime_state, tx.status, ts);

        if (sp->adjtime_state == TIME_ERROR) {
                /* Not synchronized.  Do a one-shot wait on the descriptor and inform the caller we need to keep
                 * running. */
                r = sd_event_add_io(event, &sp->event_source, sp->fd,
                                    EPOLLIN, io_handler, sp);
                if (r < 0) {
                        log_error_errno(r, "Failed to create time change monitor source: %m");
                        goto finish;
                }
                r = 1;
        } else {
                /* Synchronized; we can exit. */
                (void) sd_event_exit(event, 0);
                r = 0;
        }

 finish:
        if (r < 0)
                (void) sd_event_exit(event, r);
        return r;
}

int main(int argc,
         char * argv[]) {
        int r;
        _cleanup_(sd_event_unrefp) sd_event *event;
        ClockState state = {
                .fd = -1,
        };

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = sd_event_default(&event);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate event loop: %m");
                goto finish;
        }

        r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to create sigterm event source: %m");
                goto finish;
        }

        r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to create sigint event source: %m");
                goto finish;
        }

        r = sd_event_set_watchdog(event, true);
        if (r < 0) {
                log_error_errno(r, "Failed to create watchdog event source: %m");
                goto finish;
        }

        r = clock_state_update(&state, event);
        if (r > 0) {
                r = sd_event_loop(event);
                if (0 > r)
                        log_error_errno(r, "Failed in event loop: %m");
                else if (state.adjtime_state == TIME_ERROR) {
                        log_error("Event loop terminated without synchronizing");
                        r = -ECANCELED;
                }
        }

 finish:
        clock_state_release(&state);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
