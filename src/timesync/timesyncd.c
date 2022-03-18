/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "capability-util.h"
#include "clock-util.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "network-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "timesyncd-bus.h"
#include "timesyncd-conf.h"
#include "timesyncd-manager.h"
#include "user-util.h"

static int load_clock_timestamp(uid_t uid, gid_t gid) {
        usec_t min = TIME_EPOCH * USEC_PER_SEC, ct;
        _cleanup_close_ int fd = -1;
        int r;

        /* Let's try to make sure that the clock is always
         * monotonically increasing, by saving the clock whenever we
         * have a new NTP time, or when we shut down, and restoring it
         * when we start again. This is particularly helpful on
         * systems lacking a battery backed RTC. We also will adjust
         * the time to at least the build time of systemd. */

        fd = open(CLOCK_FILE, O_RDWR|O_CLOEXEC, 0644);
        if (fd >= 0) {
                struct stat st;
                usec_t stamp;

                /* check if the recorded time is later than the compiled-in one */
                if (fstat(fd, &st) >= 0) {
                        stamp = timespec_load(&st.st_mtim);
                        if (stamp > min)
                                min = stamp;
                }

                if (geteuid() == 0) {
                        /* Try to fix the access mode, so that we can still
                           touch the file after dropping privileges */
                        r = fchmod_and_chown(fd, 0644, uid, gid);
                        if (r < 0)
                                log_warning_errno(r, "Failed to chmod or chown %s, ignoring: %m", CLOCK_FILE);
                }

        } else {
                r = mkdir_safe_label(STATE_DIR, 0755, uid, gid,
                                     MKDIR_FOLLOW_SYMLINK | MKDIR_WARN_MODE);
                if (r < 0) {
                        log_debug_errno(r, "Failed to create state directory, ignoring: %m");
                        goto settime;
                }

                /* create stamp file with the compiled-in date */
                r = touch_file(CLOCK_FILE, /* parents= */ false, min, uid, gid, 0644);
                if (r < 0)
                        log_debug_errno(r, "Failed to create %s, ignoring: %m", CLOCK_FILE);
        }

settime:
        ct = now(CLOCK_REALTIME);
        if (ct < min) {
                char date[FORMAT_TIMESTAMP_MAX];

                log_info("System clock time unset or jumped backwards, restoring from recorded timestamp: %s",
                         format_timestamp(date, sizeof(date), min));

                if (clock_settime(CLOCK_REALTIME, TIMESPEC_STORE(min)) < 0)
                        log_error_errno(errno, "Failed to restore system clock, ignoring: %m");
        }

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

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

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
                r = touch(CLOCK_FILE);
                if (r < 0)
                        log_debug_errno(r, "Failed to touch " CLOCK_FILE ", ignoring: %m");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
