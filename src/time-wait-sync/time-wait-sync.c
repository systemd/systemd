/*
 * systemd service to wait until kernel realtime clock is synchronized
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
#include <sys/inotify.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <unistd.h>

#include "sd-event.h"

#include "fd-util.h"
#include "fs-util.h"
#include "main-func.h"
#include "missing.h"
#include "signal-util.h"
#include "time-util.h"

typedef struct ClockState {
        int timerfd_fd;                  /* non-negative is descriptor from timerfd_create */
        int adjtime_state;               /* return value from last adjtimex(2) call */
        sd_event_source *timerfd_event_source; /* non-null is the active io event source */
        int inotify_fd;
        sd_event_source *inotify_event_source;
        int run_systemd_wd;
        int run_systemd_timesync_wd;
        bool has_watchfile;
} ClockState;

static void clock_state_release_timerfd(ClockState *sp) {
        sp->timerfd_event_source = sd_event_source_unref(sp->timerfd_event_source);
        sp->timerfd_fd = safe_close(sp->timerfd_fd);
}

static void clock_state_release(ClockState *sp) {
        clock_state_release_timerfd(sp);
        sp->inotify_event_source = sd_event_source_unref(sp->inotify_event_source);
        sp->inotify_fd = safe_close(sp->inotify_fd);
}

static int clock_state_update(ClockState *sp, sd_event *event);

static int update_notify_run_systemd_timesync(ClockState *sp) {
        sp->run_systemd_timesync_wd = inotify_add_watch(sp->inotify_fd, "/run/systemd/timesync", IN_CREATE|IN_DELETE_SELF);
        return sp->run_systemd_timesync_wd;
}

static int timerfd_handler(sd_event_source *s,
                           int fd,
                           uint32_t revents,
                           void *userdata) {
        ClockState *sp = userdata;

        return clock_state_update(sp, sd_event_source_get_event(s));
}

static void process_inotify_event(sd_event *event, ClockState *sp, struct inotify_event *e) {
        if (e->wd == sp->run_systemd_wd) {
                /* Only thing we care about is seeing if we can start watching /run/systemd/timesync. */
                if (sp->run_systemd_timesync_wd < 0)
                        update_notify_run_systemd_timesync(sp);
        } else if (e->wd == sp->run_systemd_timesync_wd) {
                if (e->mask & IN_DELETE_SELF) {
                        /* Somebody removed /run/systemd/timesync. */
                        (void) inotify_rm_watch(sp->inotify_fd, sp->run_systemd_timesync_wd);
                        sp->run_systemd_timesync_wd = -1;
                } else
                        /* Somebody might have created /run/systemd/timesync/synchronized. */
                        clock_state_update(sp, event);
        }
}

static int inotify_handler(sd_event_source *s,
                           int fd,
                           uint32_t revents,
                           void *userdata) {
        sd_event *event = sd_event_source_get_event(s);
        ClockState *sp = userdata;
        union inotify_event_buffer buffer;
        struct inotify_event *e;
        ssize_t l;

        l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                return log_warning_errno(errno, "Lost access to inotify: %m");
        }
        FOREACH_INOTIFY_EVENT(e, buffer, l)
                process_inotify_event(event, sp, e);

        return 0;
}

static int clock_state_update(
                ClockState *sp,
                sd_event *event) {

        char buf[MAX((size_t)FORMAT_TIMESTAMP_MAX, STRLEN("unrepresentable"))];
        struct timex tx = {};
        const char * ts;
        usec_t t;
        int r;

        clock_state_release_timerfd(sp);

        /* The kernel supports cancelling timers whenever its realtime clock is "set" (which can happen in a variety of
         * ways, generally adjustments of at least 500 ms). The way this module works is we set up a timerfd that will
         * wake when the clock is set, and when that happens we read the clock synchronization state from the return
         * value of adjtimex(2), which supports the NTP time adjustment protocol.
         *
         * The kernel determines whether the clock is synchronized using driver-specific tests, based on time
         * information passed by an application, generally through adjtimex(2). If the application asserts the clock is
         * synchronized, but does not also do something that "sets the clock", the timer will not be cancelled and
         * synchronization will not be detected.
         *
         * Similarly, this service will never complete if the application sets the time without also providing
         * information that adjtimex(2) can use to determine that the clock is synchronized. This generally doesn't
         * happen, but can if the system has a hardware clock that is accurate enough that the adjustment is too small
         * to be a "set".
         *
         * Both these failure-to-detect situations are covered by having the presence/creation of
         * /run/systemd/timesync/synchronized, which is considered sufficient to indicate a synchronized clock even if
         * the kernel has not been updated.
         *
         * For timesyncd the initial setting of the time uses settimeofday(2), which sets the clock but does not mark
         * it synchronized. When an NTP source is selected it sets the clock again with clock_adjtime(2) which marks it
         * synchronized and also touches /run/systemd/timesync/synchronized which covers the case when the clock wasn't
         * "set". */

        r = time_change_fd();
        if (r < 0) {
                log_error_errno(r, "Failed to create timerfd: %m");
                goto finish;
        }
        sp->timerfd_fd = r;

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

        sp->has_watchfile = access("/run/systemd/timesync/synchronized", F_OK) >= 0;
        if (sp->has_watchfile)
                /* Presence of watch file overrides adjtime_state */
                r = 0;
        else if (sp->adjtime_state == TIME_ERROR) {
                /* Not synchronized.  Do a one-shot wait on the descriptor and inform the caller we need to keep
                 * running. */
                r = sd_event_add_io(event, &sp->timerfd_event_source, sp->timerfd_fd,
                                    EPOLLIN, timerfd_handler, sp);
                if (r < 0) {
                        log_error_errno(r, "Failed to create time change monitor source: %m");
                        goto finish;
                }
                r = 1;
        } else
                /* Synchronized; we can exit. */
                r = 0;

 finish:
        if (r <= 0)
                (void) sd_event_exit(event, r);
        return r;
}

static int run(int argc, char * argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *event;
        _cleanup_(clock_state_release) ClockState state = {
                .timerfd_fd = -1,
                .inotify_fd = -1,
                .run_systemd_wd = -1,
                .run_systemd_timesync_wd = -1,
        };
        int r;

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create sigterm event source: %m");

        r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create sigint event source: %m");

        r = sd_event_set_watchdog(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to create watchdog event source: %m");

        r = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (r < 0)
                return log_error_errno(errno, "Failed to create inotify descriptor: %m");

        state.inotify_fd = r;

        r = sd_event_add_io(event, &state.inotify_event_source, state.inotify_fd,
                            EPOLLIN, inotify_handler, &state);
        if (r < 0)
                return log_error_errno(r, "Failed to create notify event source: %m");

        r = inotify_add_watch(state.inotify_fd, "/run/systemd/", IN_CREATE);
        if (r < 0)
                return log_error_errno(errno, "Failed to watch /run/systemd/: %m");

        state.run_systemd_wd = r;

        (void) update_notify_run_systemd_timesync(&state);

        r = clock_state_update(&state, event);
        if (r > 0) {
                r = sd_event_loop(event);
                if (r < 0)
                        log_error_errno(r, "Failed in event loop: %m");
        }

        if (state.has_watchfile)
                log_debug("Exit enabled by: /run/systemd/timesync/synchronized");

        if (state.adjtime_state == TIME_ERROR)
                log_info("Exit without adjtimex synchronized.");

        return r;
}

DEFINE_MAIN_FUNCTION(run);
