/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <unistd.h>

#include "log.h"
#include "tests.h"
#include "watchdog.h"

int main(int argc, char *argv[]) {
        usec_t t;
        unsigned i, count;
        int r;
        bool slow;

        test_setup_logging(LOG_DEBUG);

        slow = slow_tests_enabled();

        t = slow ? 10 * USEC_PER_SEC : 2 * USEC_PER_SEC;
        count = slow ? 5 : 3;

        r = watchdog_setup(t);
        if (r < 0)
                log_warning_errno(r, "Failed to open watchdog: %m");
        if (r == -EPERM)
                t = 0;

        for (i = 0; i < count; i++) {
                t = watchdog_runtime_wait();
                log_info("Sleeping " USEC_FMT " microseconds...", t);
                usleep(t);
                log_info("Pinging...");
                r = watchdog_ping();
                if (r < 0)
                        log_warning_errno(r, "Failed to ping watchdog: %m");
        }

        watchdog_close(true);
        return 0;
}
