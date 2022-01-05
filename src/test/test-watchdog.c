/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <unistd.h>

#include "log.h"
#include "tests.h"
#include "watchdog.h"

int main(int argc, char *argv[]) {
        usec_t t;
        unsigned i;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (!slow_tests_enabled())
                return log_tests_skipped("slow tests are disabled");

        t = 10 * USEC_PER_SEC;

        r = watchdog_setup(t);
        if (r < 0)
                log_warning_errno(r, "Failed to open watchdog: %m");
        if (r == -EPERM)
                t = 0;

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
