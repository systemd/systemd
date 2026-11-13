/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "tests.h"
#include "time-util.h"
#include "watchdog.h"

TEST(watchdog) {
        int r;

        bool slow = slow_tests_enabled();

        usec_t timeout = slow ? 10 * USEC_PER_SEC : 2 * USEC_PER_SEC;
        unsigned count = slow ? 5 : 3;

        log_info("Initializing watchdog with timeout of %s", FORMAT_TIMESPAN(timeout, USEC_PER_SEC));
        r = watchdog_setup(timeout);
        if (r < 0)
                log_warning_errno(r, "Failed to open watchdog: %m");

        for (unsigned i = 0; i < count; i++) {
                timeout = watchdog_runtime_wait(/* divisor= */ 2);
                log_info("Sleeping %s…", FORMAT_TIMESPAN(timeout, USEC_PER_SEC));
                usleep_safe(timeout);
                log_info("Pinging...");
                r = watchdog_ping();
                if (r < 0)
                        log_warning_errno(r, "Failed to ping watchdog: %m");
        }

        watchdog_close(/* disarm= */ true);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
