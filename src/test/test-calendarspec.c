/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "calendarspec.h"
#include "env-util.h"
#include "errno-util.h"
#include "string-util.h"

static void _test_one(int line, const char *input, const char *output) {
        CalendarSpec *c;
        _cleanup_free_ char *p = NULL, *q = NULL;
        usec_t u;
        char buf[FORMAT_TIMESTAMP_MAX];
        int r;

        assert_se(calendar_spec_from_string(input, &c) >= 0);

        assert_se(calendar_spec_to_string(c, &p) >= 0);
        log_info("line %d: \"%s\" → \"%s\"", line, input, p);

        assert_se(streq(p, output));

        u = now(CLOCK_REALTIME);
        r = calendar_spec_next_usec(c, u, &u);
        log_info("Next: %s", r < 0 ? strerror_safe(r) : format_timestamp(buf, sizeof buf, u));
        calendar_spec_free(c);

        assert_se(calendar_spec_from_string(p, &c) >= 0);
        assert_se(calendar_spec_to_string(c, &q) >= 0);
        calendar_spec_free(c);

        assert_se(streq(q, p));
}
#define test_one(input, output) _test_one(__LINE__, input, output)

static void _test_next(int line, const char *input, const char *new_tz, usec_t after, usec_t expect) {
        CalendarSpec *c;
        usec_t u;
        char *old_tz;
        char buf[FORMAT_TIMESTAMP_MAX];
        int r;

        old_tz = getenv("TZ");
        if (old_tz)
                old_tz = strdupa(old_tz);

        if (!isempty(new_tz))
                new_tz = strjoina(":", new_tz);

        assert_se(set_unset_env("TZ", new_tz, true) == 0);
        tzset();

        assert_se(calendar_spec_from_string(input, &c) >= 0);

        log_info("line %d: \"%s\" new_tz=%s", line, input, strnull(new_tz));

        u = after;
        r = calendar_spec_next_usec(c, after, &u);
        log_info("At: %s", r < 0 ? strerror_safe(r) : format_timestamp_style(buf, sizeof buf, u, TIMESTAMP_US));
        if (expect != USEC_INFINITY)
                assert_se(r >= 0 && u == expect);
        else
                assert(r == -ENOENT);

        calendar_spec_free(c);

        assert_se(set_unset_env("TZ", old_tz, true) == 0);
        tzset();
}
#define test_next(input, new_tz, after, expect) _test_next(__LINE__, input,new_tz,after,expect)

static void test_timestamp(void) {
        char buf[FORMAT_TIMESTAMP_MAX];
        _cleanup_free_ char *t = NULL;
        CalendarSpec *c;
        usec_t x, y;

        /* Ensure that a timestamp is also a valid calendar specification. Convert forth and back */

        x = now(CLOCK_REALTIME);

        assert_se(format_timestamp_style(buf, sizeof buf, x, TIMESTAMP_US));
        log_info("%s", buf);
        assert_se(calendar_spec_from_string(buf, &c) >= 0);
        assert_se(calendar_spec_to_string(c, &t) >= 0);
        calendar_spec_free(c);
        log_info("%s", t);

        assert_se(parse_timestamp(t, &y) >= 0);
        assert_se(y == x);
}

static void test_hourly_bug_4031(void) {
        CalendarSpec *c;
        usec_t n, u, w;
        char buf[FORMAT_TIMESTAMP_MAX], zaf[FORMAT_TIMESTAMP_MAX];
        int r;

        assert_se(calendar_spec_from_string("hourly", &c) >= 0);
        n = now(CLOCK_REALTIME);
        assert_se((r = calendar_spec_next_usec(c, n, &u)) >= 0);

        log_info("Now: %s (%"PRIu64")", format_timestamp_style(buf, sizeof buf, n, TIMESTAMP_US), n);
        log_info("Next hourly: %s (%"PRIu64")", r < 0 ? strerror_safe(r) : format_timestamp_style(buf, sizeof buf, u, TIMESTAMP_US), u);

        assert_se((r = calendar_spec_next_usec(c, u, &w)) >= 0);
        log_info("Next hourly: %s (%"PRIu64")", r < 0 ? strerror_safe(r) : format_timestamp_style(zaf, sizeof zaf, w, TIMESTAMP_US), w);

        assert_se(n < u);
        assert_se(u <= n + USEC_PER_HOUR);
        assert_se(u < w);
        assert_se(w <= u + USEC_PER_HOUR);

        calendar_spec_free(c);
}

int main(int argc, char* argv[]) {
        CalendarSpec *c;

        test_one("Sat,Thu,Mon-Wed,Sat-Sun", "Mon..Thu,Sat,Sun *-*-* 00:00:00");
        test_one("Sat,Thu,Mon..Wed,Sat..Sun", "Mon..Thu,Sat,Sun *-*-* 00:00:00");
        test_one("Mon,Sun 12-*-* 2,1:23", "Mon,Sun 2012-*-* 01,02:23:00");
        test_one("Wed *-1", "Wed *-*-01 00:00:00");
        test_one("Wed-Wed,Wed *-1", "Wed *-*-01 00:00:00");
        test_one("Wed..Wed,Wed *-1", "Wed *-*-01 00:00:00");
        test_one("Wed, 17:48", "Wed *-*-* 17:48:00");
        test_one("Wednesday,", "Wed *-*-* 00:00:00");
        test_one("Wed-Sat,Tue 12-10-15 1:2:3", "Tue..Sat 2012-10-15 01:02:03");
        test_one("Wed..Sat,Tue 12-10-15 1:2:3", "Tue..Sat 2012-10-15 01:02:03");
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
        test_one("2015-10-25 01:00:00 Asia/Vladivostok", "2015-10-25 01:00:00 Asia/Vladivostok");
        test_one("weekly Pacific/Auckland", "Mon *-*-* 00:00:00 Pacific/Auckland");
        test_one("2016-03-27 03:17:00.4200005", "2016-03-27 03:17:00.420001");
        test_one("2016-03-27 03:17:00/0.42", "2016-03-27 03:17:00/0.420000");
        test_one("9..11,13:00,30", "*-*-* 09..11,13:00,30:00");
        test_one("1..3-1..3 1..3:1..3", "*-01..03-01..03 01..03:01..03:00");
        test_one("00:00:1.125..2.125", "*-*-* 00:00:01.125000..02.125000");
        test_one("00:00:1.0..3.8", "*-*-* 00:00:01..03");
        test_one("00:00:01..03", "*-*-* 00:00:01..03");
        test_one("00:00:01/2,02..03", "*-*-* 00:00:01/2,02..03");
        test_one("*-*~1 Utc", "*-*~01 00:00:00 UTC");
        test_one("*-*~05,3 ", "*-*~03,05 00:00:00");
        test_one("*-*~* 00:00:00", "*-*-* 00:00:00");
        test_one("Monday", "Mon *-*-* 00:00:00");
        test_one("Monday *-*-*", "Mon *-*-* 00:00:00");
        test_one("*-*-*", "*-*-* 00:00:00");
        test_one("*:*:*", "*-*-* *:*:*");
        test_one("*:*", "*-*-* *:*:00");
        test_one("12:*", "*-*-* 12:*:00");
        test_one("*:30", "*-*-* *:30:00");
        test_one("93..00-*-*", "1993..2000-*-* 00:00:00");
        test_one("00..07-*-*", "2000..2007-*-* 00:00:00");
        test_one("*:20..39/5", "*-*-* *:20..35/5:00");
        test_one("00:00:20..40/1", "*-*-* 00:00:20..40");
        test_one("*~03/1,03..05", "*-*~03/1,03..05 00:00:00");
        /* UNIX timestamps are always UTC */
        test_one("@1493187147", "2017-04-26 06:12:27 UTC");
        test_one("@1493187147 UTC", "2017-04-26 06:12:27 UTC");
        test_one("@0", "1970-01-01 00:00:00 UTC");
        test_one("@0 UTC", "1970-01-01 00:00:00 UTC");
        test_one("*:05..05", "*-*-* *:05:00");
        test_one("*:05..10/6", "*-*-* *:05:00");

        test_next("2016-03-27 03:17:00", "", 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00", "CET", 12345, 1459041420000000);
        test_next("2016-03-27 03:17:00", "EET", 12345, -1);
        test_next("2016-03-27 03:17:00 UTC", NULL, 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00 UTC", "", 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00 UTC", "CET", 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00 UTC", "EET", 12345, 1459048620000000);
        test_next("2016-03-27 03:17:00.420000001 UTC", "EET", 12345, 1459048620420000);
        test_next("2016-03-27 03:17:00.4200005 UTC", "EET", 12345, 1459048620420001);
        test_next("2015-11-13 09:11:23.42", "EET", 12345, 1447398683420000);
        test_next("2015-11-13 09:11:23.42/1.77", "EET", 1447398683420000, 1447398685190000);
        test_next("2015-11-13 09:11:23.42/1.77", "EET", 1447398683419999, 1447398683420000);
        test_next("Sun 16:00:00", "CET", 1456041600123456, 1456066800000000);
        test_next("*-04-31", "", 12345, -1);
        test_next("2016-02~01 UTC", "", 12345, 1456704000000000);
        test_next("Mon 2017-05~01..07 UTC", "", 12345, 1496016000000000);
        test_next("Mon 2017-05~07/1 UTC", "", 12345, 1496016000000000);
        test_next("*-*-01/5 04:00:00 UTC", "", 1646010000000000, 1646107200000000);
        test_next("*-01/7-01 04:00:00 UTC", "", 1664607600000000, 1672545600000000);
        test_next("2017-08-06 9,11,13,15,17:00 UTC", "", 1502029800000000, 1502031600000000);
        test_next("2017-08-06 9..17/2:00 UTC", "", 1502029800000000, 1502031600000000);
        test_next("2016-12-* 3..21/6:00 UTC", "", 1482613200000001, 1482634800000000);
        test_next("2017-09-24 03:30:00 Pacific/Auckland", "", 12345, 1506177000000000);
        /* Due to daylight saving time - 2017-09-24 02:30:00 does not exist */
        test_next("2017-09-24 02:30:00 Pacific/Auckland", "", 12345, -1);
        test_next("2017-04-02 02:30:00 Pacific/Auckland", "", 12345, 1491053400000000);
        /* Confirm that even though it's a time change here (backward) 02:30 happens only once */
        test_next("2017-04-02 02:30:00 Pacific/Auckland", "", 1491053400000000, -1);
        test_next("2017-04-02 03:30:00 Pacific/Auckland", "", 12345, 1491060600000000);
        /* Confirm that timezones in the Spec work regardless of current timezone */
        test_next("2017-09-09 20:42:00 Pacific/Auckland", "", 12345, 1504946520000000);
        test_next("2017-09-09 20:42:00 Pacific/Auckland", "EET", 12345, 1504946520000000);
        /* Check that we don't start looping if mktime() moves us backwards */
        test_next("Sun *-*-* 01:00:00 Europe/Dublin", "", 1616412478000000, 1617494400000000);
        test_next("Sun *-*-* 01:00:00 Europe/Dublin", "IST", 1616412478000000, 1617494400000000);

        assert_se(calendar_spec_from_string("test", &c) < 0);
        assert_se(calendar_spec_from_string(" utc", &c) < 0);
        assert_se(calendar_spec_from_string("    ", &c) < 0);
        assert_se(calendar_spec_from_string("", &c) < 0);
        assert_se(calendar_spec_from_string("7", &c) < 0);
        assert_se(calendar_spec_from_string("121212:1:2", &c) < 0);
        assert_se(calendar_spec_from_string("2000-03-05.23 00:00:00", &c) < 0);
        assert_se(calendar_spec_from_string("2000-03-05 00:00.1:00", &c) < 0);
        assert_se(calendar_spec_from_string("00:00:00/0.00000001", &c) < 0);
        assert_se(calendar_spec_from_string("00:00:00.0..00.9", &c) < 0);
        assert_se(calendar_spec_from_string("2016~11-22", &c) < 0);
        assert_se(calendar_spec_from_string("*-*~5/5", &c) < 0);
        assert_se(calendar_spec_from_string("Monday.. 12:00", &c) < 0);
        assert_se(calendar_spec_from_string("Monday..", &c) < 0);
        assert_se(calendar_spec_from_string("-00:+00/-5", &c) < 0);
        assert_se(calendar_spec_from_string("00:+00/-5", &c) < 0);
        assert_se(calendar_spec_from_string("2016- 11- 24 12: 30: 00", &c) < 0);
        assert_se(calendar_spec_from_string("*~29", &c) < 0);
        assert_se(calendar_spec_from_string("*~16..31", &c) < 0);
        assert_se(calendar_spec_from_string("12..1/2-*", &c) < 0);
        assert_se(calendar_spec_from_string("20/4:00", &c) < 0);
        assert_se(calendar_spec_from_string("00:00/60", &c) < 0);
        assert_se(calendar_spec_from_string("00:00:2300", &c) < 0);
        assert_se(calendar_spec_from_string("00:00:18446744073709551615", &c) < 0);
        assert_se(calendar_spec_from_string("@88588582097858858", &c) == -ERANGE);

        test_timestamp();
        test_hourly_bug_4031();

        return 0;
}
