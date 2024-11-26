/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pretty-print.h"
#include "random-util.h"
#include "tests.h"

#define PROGRESS_PREFIX "test:"

TEST(progress_bar) {

        draw_progress_bar(PROGRESS_PREFIX, 0);

        bool paused = false;

        for (double d = 0; d <= 100; d += 0.5) {
                usleep_safe(random_u64_range(20 * USEC_PER_MSEC));
                draw_progress_barf(d, PROGRESS_PREFIX "[" PID_FMT "]", getpid_cached());

                if (!paused && d >= 50) {
                        clear_progress_bar(PROGRESS_PREFIX);
                        fputs("Sleeping for 1s...", stdout);
                        fflush(stdout);
                        usleep_safe(USEC_PER_SEC);
                        paused = true;
                }
        }

        draw_progress_barf(100, PROGRESS_PREFIX "[" PID_FMT "]", getpid_cached());
        usleep_safe(300 * MSEC_PER_SEC);
        clear_progress_bar(PROGRESS_PREFIX "[0123456789]" );
        fputs("Done.\n", stdout);
}

DEFINE_TEST_MAIN(LOG_INFO);
