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

#include <string.h>

#include "alloc-util.h"
#include "string-util.h"
#include "util.h"

static void test_should_pass(const char *p) {
        usec_t t, q;
        char buf[FORMAT_TIMESTAMP_MAX], buf_relative[FORMAT_TIMESTAMP_RELATIVE_MAX];

        assert_se(parse_timestamp(p, &t) >= 0);
        format_timestamp_us(buf, sizeof(buf), t);
        log_info("%s", buf);

        /* Chop off timezone */
        *strrchr(buf, ' ') = 0;

        assert_se(parse_timestamp(buf, &q) >= 0);
        assert_se(q == t);

        format_timestamp_relative(buf_relative, sizeof(buf_relative), t);
        log_info("%s", strna(buf_relative));
        assert_se(parse_timestamp(buf, &q) >= 0);
}

static void test_should_parse(const char *p) {
        usec_t t;

        assert_se(parse_timestamp(p, &t) >= 0);
}

static void test_should_fail(const char *p) {
        usec_t t;

        assert_se(parse_timestamp(p, &t) < 0);
}

static void test_one(const char *p) {
        _cleanup_free_ char *with_utc;

        log_info("Test: %s", p);
        with_utc = strjoin(p, " UTC", NULL);
        test_should_pass(p);
        test_should_pass(with_utc);
}

static void test_one_noutc(const char *p) {
        _cleanup_free_ char *with_utc;

        log_info("Test: %s", p);
        with_utc = strjoin(p, " UTC", NULL);
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
        test_one_noutc("now");
        test_one("yesterday");
        test_one("today");
        test_one("tomorrow");
        test_one_noutc("+2d");
        test_one_noutc("+2y 4d");
        test_one_noutc("5months ago");
        test_one_noutc("@1395716396");
        test_should_parse("today UTC");
        test_should_fail("today UTC UTC");

        return 0;
}
