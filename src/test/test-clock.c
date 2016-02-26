/***
  This file is part of systemd.

  Copyright (C) 2016 Canonical Ltd.

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
#include <fcntl.h>

#include "macro.h"
#include "fileio.h"
#include "log.h"
#include "clock-util.h"

static void test_clock_is_localtime(void) {
        char adjtime[] = "/tmp/test-adjtime.XXXXXX";
        int fd;
        FILE* f;

        const struct scenario {
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
                /* unknown value -> defaults to UTC */
                {"0.0 0 0\n0\nFOO\n", 0},
                /* gibberish */
                {"br0ken", -EIO},
        };

        /* without an adjtime file we default to UTC */
        assert_se(clock_is_localtime("/nonexisting/adjtime") == 0);

        fd = mkostemp_safe(adjtime, O_WRONLY|O_CLOEXEC);
        assert(fd > 0);
        log_info("adjtime test file: %s", adjtime);
        f = fdopen(fd, "w");
        assert(f);

        for (size_t i = 0; i < ELEMENTSOF(scenarios); ++i) {
                log_info("scenario #%zu:, expected result %i", i, scenarios[i].expected_result);
                log_info("%s", scenarios[i].contents);
                rewind(f);
                ftruncate(fd, 0);
                assert_se(write_string_stream(f, scenarios[i].contents, false) == 0);
                assert_se(clock_is_localtime(adjtime) == scenarios[i].expected_result);
        }

        unlink(adjtime);
}

/* Test with the real /etc/adjtime */
static void test_clock_is_localtime_system(void) {
        int r;
        r = clock_is_localtime(NULL);

        if (access("/etc/adjtime", F_OK) == 0) {
                log_info("/etc/adjtime exists, clock_is_localtime() == %i", r);
                /* we cannot assert much if /etc/adjtime exists, just that we
                 * expect either an answer, or an EIO if the local file really
                 * is badly malformed. I. e. we don't expect any other error
                 * code or crash. */
                assert(r == 0 || r == 1 || r == -EIO);
        } else
                /* default is UTC if there is no /etc/adjtime */
                assert(r == 0);
}

int main(int argc, char *argv[]) {
        test_clock_is_localtime();
        test_clock_is_localtime_system();

        return 0;
}
