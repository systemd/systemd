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

        assert_se(parse_sec(" xyz ", &u) < 0);
        assert_se(parse_sec("", &u) < 0);
        assert_se(parse_sec(" . ", &u) < 0);
        assert_se(parse_sec(" 5. ", &u) < 0);
        assert_se(parse_sec(".s ", &u) < 0);
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

        assert_se(parse_nsec(" xyz ", &u) < 0);
        assert_se(parse_nsec("", &u) < 0);
        assert_se(parse_nsec(" . ", &u) < 0);
        assert_se(parse_nsec(" 5. ", &u) < 0);
        assert_se(parse_nsec(".s ", &u) < 0);
}

int main(int argc, char *argv[]) {
        test_parse_sec();
        test_parse_nsec();
        return 0;
}
