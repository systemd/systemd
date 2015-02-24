/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "time-util.h"
#include "strv.h"

static void test_parse_sec(void) {
        usec_t u;

        assert_se(parse_sec("5s", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);
        assert_se(parse_sec("5s500ms", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC + 500 * USEC_PER_MSEC);
        assert_se(parse_sec(" 5s 500ms  ", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC + 500 * USEC_PER_MSEC);
        assert_se(parse_sec(" 5.5s  ", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC + 500 * USEC_PER_MSEC);
        assert_se(parse_sec(" 5.5s 0.5ms ", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC + 500 * USEC_PER_MSEC + 500);
        assert_se(parse_sec(" .22s ", &u) >= 0);
        assert_se(u == 220 * USEC_PER_MSEC);
        assert_se(parse_sec(" .50y ", &u) >= 0);
        assert_se(u == USEC_PER_YEAR / 2);
        assert_se(parse_sec("2.5", &u) >= 0);
        assert_se(u == 2500 * USEC_PER_MSEC);
        assert_se(parse_sec(".7", &u) >= 0);
        assert_se(u == 700 * USEC_PER_MSEC);
        assert_se(parse_sec("infinity", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec(" infinity ", &u) >= 0);
        assert_se(u == USEC_INFINITY);

        assert_se(parse_sec(" xyz ", &u) < 0);
        assert_se(parse_sec("", &u) < 0);
        assert_se(parse_sec(" . ", &u) < 0);
        assert_se(parse_sec(" 5. ", &u) < 0);
        assert_se(parse_sec(".s ", &u) < 0);
        assert_se(parse_sec(" infinity .7", &u) < 0);
        assert_se(parse_sec(".3 infinity", &u) < 0);
}

static void test_parse_nsec(void) {
        nsec_t u;

        assert_se(parse_nsec("5s", &u) >= 0);
        assert_se(u == 5 * NSEC_PER_SEC);
        assert_se(parse_nsec("5s500ms", &u) >= 0);
        assert_se(u == 5 * NSEC_PER_SEC + 500 * NSEC_PER_MSEC);
        assert_se(parse_nsec(" 5s 500ms  ", &u) >= 0);
        assert_se(u == 5 * NSEC_PER_SEC + 500 * NSEC_PER_MSEC);
        assert_se(parse_nsec(" 5.5s  ", &u) >= 0);
        assert_se(u == 5 * NSEC_PER_SEC + 500 * NSEC_PER_MSEC);
        assert_se(parse_nsec(" 5.5s 0.5ms ", &u) >= 0);
        assert_se(u == 5 * NSEC_PER_SEC + 500 * NSEC_PER_MSEC + 500 * NSEC_PER_USEC);
        assert_se(parse_nsec(" .22s ", &u) >= 0);
        assert_se(u == 220 * NSEC_PER_MSEC);
        assert_se(parse_nsec(" .50y ", &u) >= 0);
        assert_se(u == NSEC_PER_YEAR / 2);
        assert_se(parse_nsec("2.5", &u) >= 0);
        assert_se(u == 2);
        assert_se(parse_nsec(".7", &u) >= 0);
        assert_se(u == 0);
        assert_se(parse_nsec("infinity", &u) >= 0);
        assert_se(u == NSEC_INFINITY);
        assert_se(parse_nsec(" infinity ", &u) >= 0);
        assert_se(u == NSEC_INFINITY);

        assert_se(parse_nsec(" xyz ", &u) < 0);
        assert_se(parse_nsec("", &u) < 0);
        assert_se(parse_nsec(" . ", &u) < 0);
        assert_se(parse_nsec(" 5. ", &u) < 0);
        assert_se(parse_nsec(".s ", &u) < 0);
        assert_se(parse_nsec(" infinity .7", &u) < 0);
        assert_se(parse_nsec(".3 infinity", &u) < 0);
}

static void test_format_timespan_one(usec_t x, usec_t accuracy) {
        char *r;
        char l[FORMAT_TIMESPAN_MAX];
        usec_t y;

        log_info(USEC_FMT"     (at accuracy "USEC_FMT")", x, accuracy);

        r = format_timespan(l, sizeof(l), x, accuracy);
        assert_se(r);

        log_info(" = <%s>", l);

        assert_se(parse_sec(l, &y) >= 0);

        log_info(" = "USEC_FMT, y);

        if (accuracy <= 0)
                accuracy = 1;

        assert_se(x / accuracy == y / accuracy);
}

static void test_format_timespan(usec_t accuracy) {
        test_format_timespan_one(0, accuracy);
        test_format_timespan_one(1, accuracy);
        test_format_timespan_one(1*USEC_PER_SEC, accuracy);
        test_format_timespan_one(999*USEC_PER_MSEC, accuracy);
        test_format_timespan_one(1234567, accuracy);
        test_format_timespan_one(12, accuracy);
        test_format_timespan_one(123, accuracy);
        test_format_timespan_one(1234, accuracy);
        test_format_timespan_one(12345, accuracy);
        test_format_timespan_one(123456, accuracy);
        test_format_timespan_one(1234567, accuracy);
        test_format_timespan_one(12345678, accuracy);
        test_format_timespan_one(1200000, accuracy);
        test_format_timespan_one(1230000, accuracy);
        test_format_timespan_one(1230000, accuracy);
        test_format_timespan_one(1234000, accuracy);
        test_format_timespan_one(1234500, accuracy);
        test_format_timespan_one(1234560, accuracy);
        test_format_timespan_one(1234567, accuracy);
        test_format_timespan_one(986087, accuracy);
        test_format_timespan_one(500 * USEC_PER_MSEC, accuracy);
        test_format_timespan_one(9*USEC_PER_YEAR/5 - 23, accuracy);
        test_format_timespan_one(USEC_INFINITY, accuracy);
}

static void test_timezone_is_valid(void) {
        assert_se(timezone_is_valid("Europe/Berlin"));
        assert_se(timezone_is_valid("Australia/Sydney"));
        assert_se(!timezone_is_valid("Europe/Do not exist"));
}

static void test_get_timezones(void) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;
        char **zone;

        r = get_timezones(&zones);
        assert_se(r == 0);

        STRV_FOREACH(zone, zones) {
                assert_se(timezone_is_valid(*zone));
        }
}

int main(int argc, char *argv[]) {
        test_parse_sec();
        test_parse_nsec();
        test_format_timespan(1);
        test_format_timespan(USEC_PER_MSEC);
        test_format_timespan(USEC_PER_SEC);
        test_timezone_is_valid();
        test_get_timezones();

        return 0;
}
