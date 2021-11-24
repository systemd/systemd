/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2016 Canonical Ltd.
***/

#include <unistd.h>
#include <fcntl.h>

#include "clock-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(clock_is_localtime) {
        _cleanup_(unlink_tempfilep) char adjtime[] = "/tmp/test-adjtime.XXXXXX";
        _cleanup_fclose_ FILE* f = NULL;

        static const struct scenario {
                const char* contents;
                int expected_result;
        } scenarios[] = {
                /* adjtime configures UTC */
                {"0.0 0 0\n0\nUTC\n", 0},
                /* adjtime configures local time */
                {"0.0 0 0\n0\nLOCAL\n", 1},
                /* no final EOL */
                {"0.0 0 0\n0\nUTC", 0},
                {"0.0 0 0\n0\nLOCAL", 1},
                /* empty value -> defaults to UTC */
                {"0.0 0 0\n0\n", 0},
                /* unknown value -> defaults to UTC */
                {"0.0 0 0\n0\nFOO\n", 0},
                /* no third line */
                {"0.0 0 0", 0},
                {"0.0 0 0\n", 0},
                {"0.0 0 0\n0", 0},
        };

        /* without an adjtime file we default to UTC */
        assert_se(clock_is_localtime("/nonexisting/adjtime") == 0);

        assert_se(fmkostemp_safe(adjtime, "w", &f) == 0);
        log_info("adjtime test file: %s", adjtime);

        for (size_t i = 0; i < ELEMENTSOF(scenarios); ++i) {
                log_info("scenario #%zu:, expected result %i", i, scenarios[i].expected_result);
                log_info("%s", scenarios[i].contents);
                rewind(f);
                assert_se(ftruncate(fileno(f), 0) == 0);
                assert_se(write_string_stream(f, scenarios[i].contents, WRITE_STRING_FILE_AVOID_NEWLINE) == 0);
                assert_se(clock_is_localtime(adjtime) == scenarios[i].expected_result);
        }
}

/* Test with the real /etc/adjtime */
TEST(clock_is_localtime_system) {
        int r;
        r = clock_is_localtime(NULL);

        if (access("/etc/adjtime", R_OK) == 0) {
                log_info("/etc/adjtime is readable, clock_is_localtime() == %i", r);
                /* if /etc/adjtime exists we expect some answer, no error or
                 * crash */
                assert_se(IN_SET(r, 0, 1));
        } else
                /* default is UTC if there is no /etc/adjtime */
                assert_se(r == 0 || ERRNO_IS_PRIVILEGE(r));
}

DEFINE_TEST_MAIN(LOG_INFO);
