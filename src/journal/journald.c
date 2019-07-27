/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#include "sd-daemon.h"
#include "sd-messages.h"

#include "format-util.h"
#include "journal-authenticate.h"
#include "journald-kmsg.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "process-util.h"
#include "sigbus.h"

int main(int argc, char *argv[]) {
        Server server;
        int r;

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return EXIT_FAILURE;
        }

        log_set_prohibit_ipc(true);
        log_set_target(LOG_TARGET_AUTO);
        log_set_facility(LOG_SYSLOG);
        log_parse_environment();
        log_open();

        umask(0022);

        sigbus_install();

        r = server_init(&server);
        if (r < 0)
                goto finish;

        server_vacuum(&server, false);
        server_flush_to_var(&server, true);
        server_flush_dev_kmsg(&server);

        log_debug("systemd-journald running as pid "PID_FMT, getpid_cached());
        server_driver_message(&server, 0,
                              "MESSAGE_ID=" SD_MESSAGE_JOURNAL_START_STR,
                              LOG_MESSAGE("Journal started"),
                              NULL);

        /* Make sure to send the usage message *after* flushing the
         * journal so entries from the runtime journals are ordered
         * before this message. See #4190 for some details. */
        server_space_usage_message(&server, NULL);

        for (;;) {
                usec_t t = USEC_INFINITY, n;

                r = sd_event_get_state(server.event);
                if (r < 0)
                        goto finish;
                if (r == SD_EVENT_FINISHED)
                        break;

                n = now(CLOCK_REALTIME);

                if (server.max_retention_usec > 0 && server.oldest_file_usec > 0) {

                        /* The retention time is reached, so let's vacuum! */
                        if (server.oldest_file_usec + server.max_retention_usec < n) {
                                log_info("Retention time reached.");
                                server_rotate(&server);
                                server_vacuum(&server, false);
                                continue;
                        }

                        /* Calculate when to rotate the next time */
                        t = server.oldest_file_usec + server.max_retention_usec - n;
                }

#if HAVE_GCRYPT
                if (server.system_journal) {
                        usec_t u;

                        if (journal_file_next_evolve_usec(server.system_journal, &u)) {
                                if (n >= u)
                                        t = 0;
                                else
                                        t = MIN(t, u - n);
                        }
                }
#endif

                r = sd_event_run(server.event, t);
                if (r < 0) {
                        log_error_errno(r, "Failed to run event loop: %m");
                        goto finish;
                }

                server_maybe_append_tags(&server);
                server_maybe_warn_forward_syslog_missed(&server);
        }

        log_debug("systemd-journald stopped as pid "PID_FMT, getpid_cached());
        server_driver_message(&server, 0,
                              "MESSAGE_ID=" SD_MESSAGE_JOURNAL_STOP_STR,
                              LOG_MESSAGE("Journal stopped"),
                              NULL);

finish:
        server_done(&server);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
