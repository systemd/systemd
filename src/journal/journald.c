/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-messages.h"

#include "format-util.h"
#include "journal-authenticate.h"
#include "journald-kmsg.h"
#include "journald-manager.h"
#include "journald-syslog.h"
#include "log.h"
#include "main-func.h"
#include "process-util.h"
#include "sigbus.h"
#include "string-util.h"
#include "terminal-util.h"
#include "time-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        const char *namespace;
        LogTarget log_target;
        int r;

        if (argc > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes one or no arguments.");

        namespace = argc > 1 ? empty_to_null(argv[1]) : NULL;

        log_set_facility(LOG_SYSLOG);

        if (namespace)
                /* If we run for a log namespace, then we ourselves can log to the main journald. */
                log_setup();
        else {
                /* So here's the deal if we run as the main journald: we can't be considered as regular
                 * daemon when it comes to logging hence LOG_TARGET_AUTO won't do the right thing for
                 * us. Hence explicitly log to the console if we're started from a console or to kmsg
                 * otherwise. */
                log_target = isatty_safe(STDERR_FILENO) ? LOG_TARGET_CONSOLE : LOG_TARGET_KMSG;

                log_set_prohibit_ipc(true); /* better safe than sorry */
                log_set_target(log_target);
                log_parse_environment();
                log_open();
        }

        umask(0022);

        sigbus_install();

        r = manager_new(&m);
        if (r < 0)
                return log_oom();

        r = manager_init(m, namespace);
        if (r < 0)
                return r;

        manager_vacuum(m, /* verbose = */ false);
        manager_flush_to_var(m, /* require_flag_file = */ true);
        manager_flush_dev_kmsg(m);

        if (m->namespace)
                log_debug("systemd-journald running as PID "PID_FMT" for namespace '%s'.", getpid_cached(), m->namespace);
        else
                log_debug("systemd-journald running as PID "PID_FMT" for the system.", getpid_cached());

        manager_driver_message(m, 0,
                               LOG_MESSAGE_ID(SD_MESSAGE_JOURNAL_START_STR),
                               LOG_MESSAGE("Journal started"));

        /* Make sure to send the usage message *after* flushing the
         * journal so entries from the runtime journals are ordered
         * before this message. See #4190 for some details. */
        manager_space_usage_message(m, NULL);

        for (;;) {
                usec_t t, n;

                r = sd_event_get_state(m->event);
                if (r < 0)
                        return log_error_errno(r, "Failed to get event loop state: %m");
                if (r == SD_EVENT_FINISHED)
                        break;

                r = sd_event_now(m->event, CLOCK_REALTIME, &n);
                if (r < 0)
                        return log_error_errno(r, "Failed to get the current time: %m");

                if (m->max_retention_usec > 0 && m->oldest_file_usec > 0) {
                        /* Calculate when to rotate the next time */
                        t = usec_sub_unsigned(usec_add(m->oldest_file_usec, m->max_retention_usec), n);

                        /* The retention time is reached, so let's vacuum! */
                        if (t <= 0) {
                                log_info("Retention time reached, vacuuming.");
                                manager_vacuum(m, /* verbose = */ false);
                                continue;
                        }
                } else
                        t = USEC_INFINITY;

#if HAVE_GCRYPT
                if (m->system_journal) {
                        usec_t u;

                        if (journal_file_next_evolve_usec(m->system_journal, &u))
                                t = MIN(t, usec_sub_unsigned(u, n));
                }
#endif

                r = sd_event_run(m->event, t);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");

                manager_maybe_append_tags(m);
                manager_maybe_warn_forward_syslog_missed(m);
        }

        if (m->namespace)
                log_debug("systemd-journald stopped as PID "PID_FMT" for namespace '%s'.", getpid_cached(), m->namespace);
        else
                log_debug("systemd-journald stopped as PID "PID_FMT" for the system.", getpid_cached());

        manager_driver_message(m, 0,
                               LOG_MESSAGE_ID(SD_MESSAGE_JOURNAL_STOP_STR),
                               LOG_MESSAGE("Journal stopped"));

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
