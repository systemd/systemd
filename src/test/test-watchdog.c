/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include <string.h>
#include <unistd.h>

#include "env-util.h"
#include "log.h"
#include "watchdog.h"

int main(int argc, char *argv[]) {
        usec_t t;
        unsigned i, count;
        int r;
        bool slow;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        r = getenv_bool("SYSTEMD_SLOW_TESTS");
        slow = r >= 0 ? r : SYSTEMD_SLOW_TESTS_DEFAULT;

        t = slow ? 10 * USEC_PER_SEC : 1 * USEC_PER_SEC;
        count = slow ? 5 : 3;

        r = watchdog_set_timeout(&t);
        if (r < 0)
                log_warning_errno(r, "Failed to open watchdog: %m");
        if (r == -EPERM)
                t = 0;

        for (i = 0; i < count; i++) {
                log_info("Pinging...");
                r = watchdog_ping();
                if (r < 0)
                        log_warning_errno(r, "Failed to ping watchdog: %m");

                usleep(t/2);
        }

        watchdog_close(true);
        return 0;
}
