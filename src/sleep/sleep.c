/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "util.h"
#include "systemd/sd-id128.h"
#include "systemd/sd-messages.h"

int main(int argc, char *argv[]) {
        const char *verb;
        char* arguments[4];
        int r;
        FILE *f;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 2) {
                log_error("Invalid number of arguments.");
                r = -EINVAL;
                goto finish;
        }

        if (streq(argv[1], "suspend"))
                verb = "mem";
        else if (streq(argv[1], "hibernate"))
                verb = "disk";
        else {
                log_error("Unknown action '%s'.", argv[1]);
                r = -EINVAL;
                goto finish;
        }

        f = fopen("/sys/power/state", "we");
        if (!f) {
                log_error("Failed to open /sys/power/state: %m");
                r = -errno;
                goto finish;
        }

        arguments[0] = NULL;
        arguments[1] = (char*) "pre";
        arguments[2] = argv[1];
        arguments[3] = NULL;
        execute_directory(SYSTEM_SLEEP_PATH, NULL, arguments);

        if (streq(argv[1], "suspend"))
                log_struct(LOG_INFO,
                           MESSAGE_ID(SD_MESSAGE_SLEEP_START),
                           "MESSAGE=Suspending system...",
                           "SLEEP=suspend",
                           NULL);
        else
                log_struct(LOG_INFO,
                           MESSAGE_ID(SD_MESSAGE_SLEEP_START),
                           "MESSAGE=Hibernating system...",
                           "SLEEP=hibernate",
                           NULL);

        fputs(verb, f);
        fputc('\n', f);
        fflush(f);

        r = ferror(f) ? -errno : 0;

        if (streq(argv[1], "suspend"))
                log_struct(LOG_INFO,
                           MESSAGE_ID(SD_MESSAGE_SLEEP_STOP),
                           "MESSAGE=System resumed.",
                           "SLEEP=suspend",
                           NULL);
        else
                log_struct(LOG_INFO,
                           MESSAGE_ID(SD_MESSAGE_SLEEP_STOP),
                           "MESSAGE=System thawed.",
                           "SLEEP=hibernate",
                           NULL);

        arguments[1] = (char*) "post";
        execute_directory(SYSTEM_SLEEP_PATH, NULL, arguments);

        fclose(f);

finish:

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

}
