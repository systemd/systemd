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

#include <unistd.h>

#include "watchdog.h"
#include "log.h"

int main(int argc, char *argv[]) {
        usec_t t = 10 * USEC_PER_SEC;
        unsigned i;
        int r;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        r = watchdog_set_timeout(&t);
        if (r < 0)
                log_warning_errno(r, "Failed to open watchdog: %m");

        for (i = 0; i < 5; i++) {
                log_info("Pinging...");
                r = watchdog_ping();
                if (r < 0)
                        log_warning_errno(r, "Failed to ping watchdog: %m");

                usleep(t/2);
        }

        watchdog_close(true);
        return 0;
}
