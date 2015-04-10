/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>

#include "systemd/sd-messages.h"
#include "systemd/sd-daemon.h"

#include "journal-authenticate.h"
#include "journald-server.h"
#include "journald-kmsg.h"
#include "journald-syslog.h"

#include "sigbus.h"
#include "formats-util.h"

int main(int argc, char *argv[]) {
        Server server;
        int r;

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_SAFE);
        log_set_facility(LOG_SYSLOG);
        log_parse_environment();
        log_open();

        umask(0022);

        sigbus_install();

        r = server_init(&server);
        if (r < 0)
                goto finish;

        server_vacuum(&server);
        server_flush_to_var(&server);
        server_flush_dev_kmsg(&server);

        log_debug("systemd-journald running as pid "PID_FMT, getpid());
        server_driver_message(&server, SD_MESSAGE_JOURNAL_START, "Journal started");

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

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
                                server_vacuum(&server);
                                continue;
                        }

                        /* Calculate when to rotate the next time */
                        t = server.oldest_file_usec + server.max_retention_usec - n;
                }

#ifdef HAVE_GCRYPT
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

        log_debug("systemd-journald stopped as pid "PID_FMT, getpid());
        server_driver_message(&server, SD_MESSAGE_JOURNAL_STOP, "Journal stopped");

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

        server_done(&server);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
