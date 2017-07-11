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

#include "alloc-util.h"
#include "string-util.h"
#include "util.h"

static void test_should_pass(const char *p) {
        usec_t t, q;
        char buf[FORMAT_TIMESTAMP_MAX], buf_relative[FORMAT_TIMESTAMP_RELATIVE_MAX];

        log_info("Test: %s", p);
        assert_se(parse_timestamp(p, &t) >= 0);
        assert_se(format_timestamp_us(buf, sizeof(buf), t));
        log_info("\"%s\" → \"%s\"", p, buf);

        assert_se(parse_timestamp(buf, &q) >= 0);
        assert_se(q == t);

        assert_se(format_timestamp_relative(buf_relative, sizeof(buf_relative), t));
        log_info("%s", strna(buf_relative));
}

static void test_should_parse(const char *p) {
        usec_t t;

        log_info("Test: %s", p);
        assert_se(parse_timestamp(p, &t) >= 0);
        log_info("\"%s\" → \"@%" PRI_USEC "\"", p, t);
}

static void test_should_fail(const char *p) {
        usec_t t;
        int r;

        log_info("Test: %s", p);
        r = parse_timestamp(p, &t);
        if (r >= 0)
                log_info("\"%s\" → \"@%" PRI_USEC "\" (unexpected)", p, t);
        else
                log_info("parse_timestamp() returns %d (expected)", r);
        assert_se(r < 0);
}

static void test_one(const char *p) {
        _cleanup_free_ char *with_utc;

        with_utc = strjoin(p, " UTC");
        test_should_pass(p);
        test_should_pass(with_utc);
}

static void test_one_noutc(const char *p) {
        _cleanup_free_ char *with_utc;

        with_utc = strjoin(p, " UTC");
        test_should_pass(p);
        test_should_fail(with_utc);
}

int main(int argc, char *argv[]) {
        test_one("17:41");
        test_one("18:42:44");
        test_one("18:42:44.0");
        test_one("18:42:44.999999999999");
        test_one("12-10-02 12:13:14");
        test_one("12-10-2 12:13:14");
        test_one("12-10-03 12:13");
        test_one("2012-12-30 18:42");
        test_one("2012-10-02");
        test_one("Tue 2012-10-02");
        test_one("yesterday");
        test_one("today");
        test_one("tomorrow");
        test_one_noutc("now");
        test_one_noutc("+2d");
        test_one_noutc("+2y 4d");
        test_one_noutc("5months ago");
        test_one_noutc("@1395716396");
        test_should_parse("1970-1-1 UTC");
        test_should_pass("1970-1-1 00:00:01 UTC");
        test_should_fail("1969-12-31 UTC");
        test_should_fail("-100y");
        test_should_fail("today UTC UTC");
#if SIZEOF_TIME_T == 8
        test_should_pass("9999-12-30 23:59:59 UTC");
        test_should_fail("9999-12-31 00:00:00 UTC");
        test_should_fail("10000-01-01 00:00:00 UTC");
#elif SIZEOF_TIME_T == 4
        test_should_pass("2038-01-19 03:14:07 UTC");
        test_should_fail("2038-01-19 03:14:08 UTC");
#endif

        return 0;
}
