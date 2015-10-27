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
#include "calendarspec.h"
#include "string-util.h"
#include "util.h"

static void test_one(const char *input, const char *output) {
        CalendarSpec *c;
        _cleanup_free_ char *p = NULL, *q = NULL;
        usec_t u;
        char buf[FORMAT_TIMESTAMP_MAX];
        int r;

        assert_se(calendar_spec_from_string(input, &c) >= 0);

        assert_se(calendar_spec_to_string(c, &p) >= 0);
        printf("\"%s\" → \"%s\"\n", input, p);

        assert_se(streq(p, output));

        u = now(CLOCK_REALTIME);
        r = calendar_spec_next_usec(c, u, &u);
        printf("Next: %s\n", r < 0 ? strerror(-r) : format_timestamp(buf, sizeof(buf), u));
        calendar_spec_free(c);

        assert_se(calendar_spec_from_string(p, &c) >= 0);
        assert_se(calendar_spec_to_string(c, &q) >= 0);
        calendar_spec_free(c);

        assert_se(streq(q, p));
}

static void test_next(const char *input, const char *new_tz, usec_t after, usec_t expect) {
        CalendarSpec *c;
        usec_t u;
        char *old_tz;
        char buf[FORMAT_TIMESTAMP_MAX];
        int r;

        old_tz = getenv("TZ");
        if (old_tz)
                old_tz = strdupa(old_tz);

        if (new_tz)
                assert_se(setenv("TZ", new_tz, 1) >= 0);
        else
                assert_se(unsetenv("TZ") >= 0);
        tzset();

        assert_se(calendar_spec_from_string(input, &c) >= 0);

        printf("\"%s\"\n", input);

        u = after;
        r = calendar_spec_next_usec(c, after, &u);
        printf("At: %s\n", r < 0 ? strerror(-r) : format_timestamp(buf, sizeof(buf), u));
        if (expect != (usec_t)-1)
                assert_se(r >= 0 && u == expect);
        else
                assert(r == -ENOENT);

        calendar_spec_free(c);

        if (old_tz)
                assert_se(setenv("TZ", old_tz, 1) >= 0);
        else
                assert_se(unsetenv("TZ") >= 0);
        tzset();
}

int main(int argc, char* argv[]) {
        CalendarSpec *c;

        test_one("Sat,Thu,Mon-Wed,Sat-Sun", "Mon-Thu,Sat,Sun *-*-* 00:00:00");
        test_one("Mon,Sun 12-*-* 2,1:23", "Mon,Sun 2012-*-* 01,02:23:00");
        test_one("Wed *-1", "Wed *-*-01 00:00:00");
        test_one("Wed-Wed,Wed *-1", "Wed *-*-01 00:00:00");
        test_one("Wed, 17:48", "Wed *-*-* 17:48:00");
        test_one("Wed-Sat,Tue 12-10-15 1:2:3", "Tue-Sat 2012-10-15 01:02:03");
        test_one("*-*-7 0:0:0", "*-*-07 00:00:00");
        test_one("10-15", "*-10-15 00:00:00");
        test_one("monday *-12-* 17:00", "Mon *-12-* 17:00:00");
        test_one("Mon,Fri *-*-3,1,2 *:30:45", "Mon,Fri *-*-01,02,03 *:30:45");
        test_one("12,14,13,12:20,10,30", "*-*-* 12,13,14:10,20,30:00");
        test_one("mon,fri *-1/2-1,3 *:30:45", "Mon,Fri *-01/2-01,03 *:30:45");
        test_one("03-05 08:05:40", "*-03-05 08:05:40");
        test_one("08:05:40", "*-*-* 08:05:40");
        test_one("05:40", "*-*-* 05:40:00");
        test_one("Sat,Sun 12-05 08:05:40", "Sat,Sun *-12-05 08:05:40");
        test_one("Sat,Sun 08:05:40", "Sat,Sun *-*-* 08:05:40");
        test_one("2003-03-05 05:40", "2003-03-05 05:40:00");
        test_one("2003-03-05", "2003-03-05 00:00:00");
        test_one("03-05", "*-03-05 00:00:00");
        test_one("hourly", "*-*-* *:00:00");
        test_one("daily", "*-*-* 00:00:00");
        test_one("monthly", "*-*-01 00:00:00");
        test_one("weekly", "Mon *-*-* 00:00:00");
        test_one("minutely", "*-*-* *:*:00");
        test_one("quarterly", "*-01,04,07,10-01 00:00:00");
        test_one("semi-annually", "*-01,07-01 00:00:00");
        test_one("annually", "*-01-01 00:00:00");
        test_one("*:2/3", "*-*-* *:02/3:00");
        test_one("2015-10-25 01:00:00 uTc", "2015-10-25 01:00:00 UTC");

        test_next("2016-03-27 03:17:00", "", 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00", "CET", 12345, 1459041420000000);
        test_next("2016-03-27 03:17:00", "EET", 12345, -1);
        test_next("2016-03-27 03:17:00 UTC", NULL, 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00 UTC", "", 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00 UTC", "CET", 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00 UTC", "EET", 12345, 1459048620000000);

        assert_se(calendar_spec_from_string("test", &c) < 0);
        assert_se(calendar_spec_from_string("", &c) < 0);
        assert_se(calendar_spec_from_string("7", &c) < 0);
        assert_se(calendar_spec_from_string("121212:1:2", &c) < 0);

        return 0;
}
