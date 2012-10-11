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

#include "util.h"

int main(int argc, char *argv[]) {

        usec_t t;
        char buf[FORMAT_TIMESTAMP_MAX];

        assert_se(parse_timestamp("17:41", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("18:42:44", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("12-10-02 12:13:14", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("12-10-2 12:13:14", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("12-10-03 12:13", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("2012-12-30 18:42", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("2012-10-02", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("now", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("yesterday", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("today", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("tomorrow", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("+2d", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        assert_se(parse_timestamp("+2y 4d", &t) >= 0);
        log_info("%s", format_timestamp(buf, sizeof(buf), t));

        return 0;
}
