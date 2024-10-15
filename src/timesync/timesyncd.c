/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-messages.h"

#include "bus-log-control-api.h"
#include "capability-util.h"
#include "clock-util.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "network-util.h"
#include "process-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "timesyncd-bus.h"
#include "timesyncd-conf.h"
#include "timesyncd-manager.h"
#include "user-util.h"

static int advance_tstamp(int fd, usec_t epoch) {
        assert(fd >= 0);

        /* So here's the problem: whenever we read the timestamp we'd like to ensure the next time we won't
         * restore the exact same time again, but one at least one step further (so that comparing mtimes of
         * the timestamp file is a reliable check that timesync did its thing). But file systems have
         * different timestamp accuracy: traditional fat has 2s granularity, and even ext2 and friends expose
         * different granularity depending on selected inode size during formatting! Hence, to ensure the
         * timestamp definitely is increased, here's what we'll do: we'll first try to increase the timestamp
         * by 1μs, write that and read it back. If it was updated, great. But if it was not, we'll instead
         * increase the timestamp by 10μs, and do the same, then 100μs, then 1ms, and so on, until it works,
         * or we reach 10s. If it still didn't work then, the fs is just broken and we give up. */

        usec_t target = MAX(epoch, now(CLOCK_REALTIME));

        for (usec_t a = 1; a <= 10 * USEC_PER_SEC; a *= 10) { /* 1μs, 10μs, 100μs, 1ms, … 10s */
                struct timespec ts[2];
                struct stat new_st;

                /* Bump to the maximum of the old timestamp advanced by the specified unit. */
                usec_t c = usec_add(target, a);

                timespec_store(&ts[0], c);
                ts[1] = ts[0];

                if (futimens(fd, ts) < 0) {
                        /* If this doesn't work at all, log and don't fail, but give up. */
                        log_warning_errno(errno, "Unable to update mtime of timestamp file, ignoring: %m");
                        return 0;
                }

                if (fstat(fd, &new_st) < 0)
                        return log_error_errno(errno, "Failed to stat timestamp file: %m");

                if (timespec_load(&new_st.st_mtim) > target) {
                        log_debug("Successfully touched timestamp file.");
                        return 1;
                }

                log_debug("Tried to advance timestamp mtime by "USEC_FMT", but this didn't work, file system timestamp granularity too coarse?", a);
        }

        log_debug("Gave up trying to advance timestamp file.");
        return 0;
}

static int load_clock_timestamp(uid_t uid, gid_t gid) {
        usec_t epoch = TIME_EPOCH * USEC_PER_SEC, ct;
        _cleanup_close_ int fd = -EBADF;
        int r;

        /* Let's try to make sure that the clock is always monotonically increasing, by saving the clock
         * whenever we have a new NTP time, or when we shut down, and restoring it when we start again. This
         * is particularly helpful on systems lacking a battery backed RTC. We also will adjust the time to
         * at least the build time of systemd. */

        fd = open(TIMESYNCD_CLOCK_FILE, O_RDWR|O_CLOEXEC, 0644);
        if (fd < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Unable to open timestamp file "TIMESYNCD_CLOCK_FILE", ignoring: %m");

                r = mkdir_safe_label(TIMESYNCD_CLOCK_FILE_DIR, 0755, uid, gid,
                                     MKDIR_FOLLOW_SYMLINK | MKDIR_WARN_MODE);
                if (r < 0)
                        log_debug_errno(r, "Failed to create "TIMESYNCD_CLOCK_FILE_DIR", ignoring: %m");

                /* Create stamp file with the compiled-in date */
                r = touch_file(TIMESYNCD_CLOCK_FILE, /* parents= */ false, epoch, uid, gid, 0644);
                if (r < 0)
                        log_debug_errno(r, "Failed to create %s, ignoring: %m", TIMESYNCD_CLOCK_FILE);
        } else {
                struct stat st;

                /* Check if the recorded time is later than the compiled-in one */
                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Unable to stat timestamp file "TIMESYNCD_CLOCK_FILE": %m");

                /* Try to fix the access mode, so that we can still touch the file after dropping
                 * privileges */
                r = fchmod_and_chown(fd, 0644, uid, gid);
                if (r < 0)
                        log_full_errno(ERRNO_IS_PRIVILEGE(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to chmod or chown %s, ignoring: %m", TIMESYNCD_CLOCK_FILE);

                epoch = MAX(epoch, timespec_load(&st.st_mtim));

                (void) advance_tstamp(fd, epoch);
        }

        ct = now(CLOCK_REALTIME);
        if (ct > epoch)
                return 0;

        /* Not that it matters much, but we actually restore the clock to n+1 here rather than n, simply
         * because we read n as time previously already and we want to progress here, i.e. not report the
         * same time again. */
        if (clock_settime(CLOCK_REALTIME, TIMESPEC_STORE(epoch + 1)) < 0) {
                log_warning_errno(errno, "Failed to advance system clock, ignoring: %m");
                return 0;
        }

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_TIME_BUMP_STR,
                   "REALTIME_USEC=" USEC_FMT, epoch + 1,
                   "DIRECTION=forwards",
                   LOG_MESSAGE("System clock time advanced to %s: %s",
                               epoch > TIME_EPOCH * USEC_PER_SEC ? "recorded timestamp" : "built-in epoch",
                               FORMAT_TIMESTAMP(epoch + 1)));
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        const char *user = "systemd-timesync";
        uid_t uid, uid_current;
        gid_t gid;
        int r;

        log_set_facility(LOG_CRON);
        log_setup();

        r = service_parse_argv("systemd-timesyncd.service",
                               "Network time synchronization",
                               BUS_IMPLEMENTATIONS(&manager_object, &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program does not take arguments.");

        uid = uid_current = geteuid();
        gid = getegid();

        if (uid_current == 0) {
                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Cannot resolve user name %s: %m", user);
        }

        r = load_clock_timestamp(uid, gid);
        if (r < 0)
                return r;

        /* Drop privileges, but only if we have been started as root. If we are not running as root we assume all
         * privileges are already dropped. */
        if (uid_current == 0) {
                r = drop_privileges(uid, gid, (1ULL << CAP_SYS_TIME));
                if (r < 0)
                        return log_error_errno(r, "Failed to drop privileges: %m");
        }

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager: %m");

        r = manager_connect_bus(m);
        if (r < 0)
                return log_error_errno(r, "Could not connect to bus: %m");

        if (clock_is_localtime(NULL) > 0) {
                log_info("The system is configured to read the RTC time in the local time zone. "
                         "This mode cannot be fully supported. All system time to RTC updates are disabled.");
                m->rtc_local_time = true;
        }

        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse configuration file: %m");

        r = manager_parse_fallback_string(m, NTP_SERVERS);
        if (r < 0)
                return log_error_errno(r, "Failed to parse fallback server strings: %m");

        log_debug("systemd-timesyncd running as pid " PID_FMT, getpid_cached());

        notify_message = notify_start("READY=1\n"
                                      "STATUS=Daemon is running",
                                      NOTIFY_STOPPING);

        r = manager_setup_save_time_event(m);
        if (r < 0)
                return r;

        if (network_is_online()) {
                r = manager_connect(m);
                if (r < 0)
                        return r;
        }

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        /* if we got an authoritative time, store it in the file system */
        if (m->save_on_exit) {
                r = touch(TIMESYNCD_CLOCK_FILE);
                if (r < 0)
                        log_debug_errno(r, "Failed to touch "TIMESYNCD_CLOCK_FILE", ignoring: %m");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
