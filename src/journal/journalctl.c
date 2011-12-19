/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/poll.h>

#include "sd-journal.h"
#include "log.h"

static bool arg_follow = true;

int main(int argc, char *argv[]) {
        int r, i, fd;
        sd_journal *j = NULL;

        log_set_max_level(LOG_DEBUG);
        log_set_target(LOG_TARGET_CONSOLE);

        log_parse_environment();
        log_open();

        r = sd_journal_open(&j);
        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                goto finish;
        }

        for (i = 1; i < argc; i++) {
                r = sd_journal_add_match(j, argv[i], strlen(argv[i]));
                if (r < 0) {
                        log_error("Failed to add match: %s", strerror(-r));
                        goto finish;
                }
        }

        fd = sd_journal_get_fd(j);
        if (fd < 0) {
                log_error("Failed to get wakeup fd: %s", strerror(-fd));
                goto finish;
        }

        r = sd_journal_seek_head(j);
        if (r < 0) {
                log_error("Failed to seek to head: %s", strerror(-r));
                goto finish;
        }

        for (;;) {
                struct pollfd pollfd;

                while (sd_journal_next(j) > 0) {
                        const void *data;
                        size_t length;
                        char *cursor;
                        uint64_t realtime = 0, monotonic = 0;

                        r = sd_journal_get_cursor(j, &cursor);
                        if (r < 0) {
                                log_error("Failed to get cursor: %s", strerror(-r));
                                goto finish;
                        }

                        printf("entry: %s\n", cursor);
                        free(cursor);

                        sd_journal_get_realtime_usec(j, &realtime);
                        sd_journal_get_monotonic_usec(j, &monotonic, NULL);
                        printf("realtime: %llu\n"
                               "monotonic: %llu\n",
                               (unsigned long long) realtime,
                               (unsigned long long) monotonic);

                        SD_JOURNAL_FOREACH_DATA(j, data, length)
                                printf("\t%.*s\n", (int) length, (const char*) data);
                }

                if (!arg_follow)
                        break;

                zero(pollfd);
                pollfd.fd = fd;
                pollfd.events = POLLIN;

                if (poll(&pollfd, 1, -1) < 0) {
                        if (errno == EINTR)
                                break;

                        log_error("poll(): %m");
                        r = -errno;
                        goto finish;
                }

                r = sd_journal_process(j);
                if (r < 0) {
                        log_error("Failed to process: %s", strerror(-r));
                        goto finish;
                }
        }

finish:
        if (j)
                sd_journal_close(j);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
