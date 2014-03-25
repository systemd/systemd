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

#include "util.h"

static void test_one(const char *p) {
        usec_t t, q;
        char buf[FORMAT_TIMESTAMP_MAX], buf_relative[FORMAT_TIMESTAMP_RELATIVE_MAX];

        assert_se(parse_timestamp(p, &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        /* Chop off timezone */
        *strrchr(buf, ' ') = 0;

        assert_se(parse_timestamp(buf, &q) >= 0);
        assert_se(q == t);

        log_info("%s", strna(format_timestamp_relative(buf_relative, sizeof(buf_relative), t)));
        assert_se(parse_timestamp(buf, &q) >= 0);
}

int main(int argc, char *argv[]) {
        test_one("17:41");
        test_one("18:42:44");
        test_one("12-10-02 12:13:14");
        test_one("12-10-2 12:13:14");
        test_one("12-10-03 12:13");
        test_one("2012-12-30 18:42");
        test_one("2012-10-02");
        test_one("Tue 2012-10-02");
        test_one("now");
        test_one("yesterday");
        test_one("today");
        test_one("tomorrow");
        test_one("+2d");
        test_one("+2y 4d");
        test_one("5months ago");
        test_one("@1395716396");

        return 0;
}
