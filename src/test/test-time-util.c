/* SPDX-License-Identifier: LGPL-2.1+ */

#include "random-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

static void test_parse_sec(void) {
        usec_t u;

        log_info("/* %s */", __func__);

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
        assert_se(parse_sec("23us", &u) >= 0);
        assert_se(u == 23);
        assert_se(parse_sec("23µs", &u) >= 0);
        assert_se(u == 23);
        assert_se(parse_sec("infinity", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec(" infinity ", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec("+3.1s", &u) >= 0);
        assert_se(u == 3100 * USEC_PER_MSEC);
        assert_se(parse_sec("3.1s.2", &u) >= 0);
        assert_se(u == 3300 * USEC_PER_MSEC);
        assert_se(parse_sec("3.1 .2", &u) >= 0);
        assert_se(u == 3300 * USEC_PER_MSEC);
        assert_se(parse_sec("3.1 sec .2 sec", &u) >= 0);
        assert_se(u == 3300 * USEC_PER_MSEC);
        assert_se(parse_sec("3.1 sec 1.2 sec", &u) >= 0);
        assert_se(u == 4300 * USEC_PER_MSEC);

        assert_se(parse_sec(" xyz ", &u) < 0);
        assert_se(parse_sec("", &u) < 0);
        assert_se(parse_sec(" . ", &u) < 0);
        assert_se(parse_sec(" 5. ", &u) < 0);
        assert_se(parse_sec(".s ", &u) < 0);
        assert_se(parse_sec("-5s ", &u) < 0);
        assert_se(parse_sec("-0.3s ", &u) < 0);
        assert_se(parse_sec("-0.0s ", &u) < 0);
        assert_se(parse_sec("-0.-0s ", &u) < 0);
        assert_se(parse_sec("0.-0s ", &u) < 0);
        assert_se(parse_sec("3.-0s ", &u) < 0);
        assert_se(parse_sec(" infinity .7", &u) < 0);
        assert_se(parse_sec(".3 infinity", &u) < 0);
        assert_se(parse_sec("3.+1s", &u) < 0);
        assert_se(parse_sec("3. 1s", &u) < 0);
        assert_se(parse_sec("3.s", &u) < 0);
        assert_se(parse_sec("12.34.56", &u) < 0);
        assert_se(parse_sec("12..34", &u) < 0);
        assert_se(parse_sec("..1234", &u) < 0);
        assert_se(parse_sec("1234..", &u) < 0);
}

static void test_parse_sec_fix_0(void) {
        usec_t u;

        log_info("/* %s */", __func__);

        assert_se(parse_sec_fix_0("5s", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);
        assert_se(parse_sec_fix_0("0s", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec_fix_0("0", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec_fix_0(" 0", &u) >= 0);
        assert_se(u == USEC_INFINITY);
}

static void test_parse_sec_def_infinity(void) {
        usec_t u;

        log_info("/* %s */", __func__);

        assert_se(parse_sec_def_infinity("5s", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);
        assert_se(parse_sec_def_infinity("", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec_def_infinity("     ", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec_def_infinity("0s", &u) >= 0);
        assert_se(u == 0);
        assert_se(parse_sec_def_infinity("0", &u) >= 0);
        assert_se(u == 0);
        assert_se(parse_sec_def_infinity(" 0", &u) >= 0);
        assert_se(u == 0);
        assert_se(parse_sec_def_infinity("-5s", &u) < 0);
}

static void test_parse_time(void) {
        usec_t u;

        log_info("/* %s */", __func__);

        assert_se(parse_time("5", &u, 1) >= 0);
        assert_se(u == 5);

        assert_se(parse_time("5", &u, USEC_PER_MSEC) >= 0);
        assert_se(u == 5 * USEC_PER_MSEC);

        assert_se(parse_time("5", &u, USEC_PER_SEC) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);

        assert_se(parse_time("5s", &u, 1) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);

        assert_se(parse_time("5s", &u, USEC_PER_SEC) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);

        assert_se(parse_time("5s", &u, USEC_PER_MSEC) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);

        assert_se(parse_time("11111111111111y", &u, 1) == -ERANGE);
        assert_se(parse_time("1.1111111111111y", &u, 1) >= 0);
}

static void test_parse_nsec(void) {
        nsec_t u;

        log_info("/* %s */", __func__);

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
        assert_se(parse_nsec("+3.1s", &u) >= 0);
        assert_se(u == 3100 * NSEC_PER_MSEC);
        assert_se(parse_nsec("3.1s.2", &u) >= 0);
        assert_se(u == 3100 * NSEC_PER_MSEC);
        assert_se(parse_nsec("3.1 .2s", &u) >= 0);
        assert_se(u == 200 * NSEC_PER_MSEC + 3);
        assert_se(parse_nsec("3.1 sec .2 sec", &u) >= 0);
        assert_se(u == 3300 * NSEC_PER_MSEC);
        assert_se(parse_nsec("3.1 sec 1.2 sec", &u) >= 0);
        assert_se(u == 4300 * NSEC_PER_MSEC);

        assert_se(parse_nsec(" xyz ", &u) < 0);
        assert_se(parse_nsec("", &u) < 0);
        assert_se(parse_nsec(" . ", &u) < 0);
        assert_se(parse_nsec(" 5. ", &u) < 0);
        assert_se(parse_nsec(".s ", &u) < 0);
        assert_se(parse_nsec(" infinity .7", &u) < 0);
        assert_se(parse_nsec(".3 infinity", &u) < 0);
        assert_se(parse_nsec("-5s ", &u) < 0);
        assert_se(parse_nsec("-0.3s ", &u) < 0);
        assert_se(parse_nsec("-0.0s ", &u) < 0);
        assert_se(parse_nsec("-0.-0s ", &u) < 0);
        assert_se(parse_nsec("0.-0s ", &u) < 0);
        assert_se(parse_nsec("3.-0s ", &u) < 0);
        assert_se(parse_nsec(" infinity .7", &u) < 0);
        assert_se(parse_nsec(".3 infinity", &u) < 0);
        assert_se(parse_nsec("3.+1s", &u) < 0);
        assert_se(parse_nsec("3. 1s", &u) < 0);
        assert_se(parse_nsec("3.s", &u) < 0);
        assert_se(parse_nsec("12.34.56", &u) < 0);
        assert_se(parse_nsec("12..34", &u) < 0);
        assert_se(parse_nsec("..1234", &u) < 0);
        assert_se(parse_nsec("1234..", &u) < 0);
        assert_se(parse_nsec("1111111111111y", &u) == -ERANGE);
        assert_se(parse_nsec("1.111111111111y", &u) >= 0);
}

static void test_format_timespan_one(usec_t x, usec_t accuracy) {
        char l[FORMAT_TIMESPAN_MAX];
        const char *t;
        usec_t y;

        log_info(USEC_FMT"     (at accuracy "USEC_FMT")", x, accuracy);

        assert_se(t = format_timespan(l, sizeof l, x, accuracy));
        log_info(" = <%s>", t);

        assert_se(parse_sec(t, &y) >= 0);
        log_info(" = "USEC_FMT, y);

        if (accuracy <= 0)
                accuracy = 1;

        assert_se(x / accuracy == y / accuracy);
}

static void test_format_timespan(usec_t accuracy) {
        log_info("/* %s accuracy="USEC_FMT" */", __func__, accuracy);

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
        log_info("/* %s */", __func__);

        assert_se(timezone_is_valid("Europe/Berlin", LOG_ERR));
        assert_se(timezone_is_valid("Australia/Sydney", LOG_ERR));
        assert_se(!timezone_is_valid("Europe/Do not exist", LOG_ERR));
}

static void test_get_timezones(void) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;
        char **zone;

        log_info("/* %s */", __func__);

        r = get_timezones(&zones);
        assert_se(r == 0);

        STRV_FOREACH(zone, zones) {
                log_info("zone: %s", *zone);
                assert_se(timezone_is_valid(*zone, LOG_ERR));
        }
}

static void test_usec_add(void) {
        log_info("/* %s */", __func__);

        assert_se(usec_add(0, 0) == 0);
        assert_se(usec_add(1, 4) == 5);
        assert_se(usec_add(USEC_INFINITY, 5) == USEC_INFINITY);
        assert_se(usec_add(5, USEC_INFINITY) == USEC_INFINITY);
        assert_se(usec_add(USEC_INFINITY-5, 2) == USEC_INFINITY-3);
        assert_se(usec_add(USEC_INFINITY-2, 2) == USEC_INFINITY);
        assert_se(usec_add(USEC_INFINITY-1, 2) == USEC_INFINITY);
        assert_se(usec_add(USEC_INFINITY, 2) == USEC_INFINITY);
}

static void test_usec_sub_unsigned(void) {
        log_info("/* %s */", __func__);

        assert_se(usec_sub_unsigned(0, 0) == 0);
        assert_se(usec_sub_unsigned(0, 2) == 0);
        assert_se(usec_sub_unsigned(0, USEC_INFINITY) == 0);
        assert_se(usec_sub_unsigned(1, 0) == 1);
        assert_se(usec_sub_unsigned(1, 1) == 0);
        assert_se(usec_sub_unsigned(1, 2) == 0);
        assert_se(usec_sub_unsigned(1, 3) == 0);
        assert_se(usec_sub_unsigned(1, USEC_INFINITY) == 0);
        assert_se(usec_sub_unsigned(USEC_INFINITY-1, 0) == USEC_INFINITY-1);
        assert_se(usec_sub_unsigned(USEC_INFINITY-1, 1) == USEC_INFINITY-2);
        assert_se(usec_sub_unsigned(USEC_INFINITY-1, 2) == USEC_INFINITY-3);
        assert_se(usec_sub_unsigned(USEC_INFINITY-1, USEC_INFINITY-2) == 1);
        assert_se(usec_sub_unsigned(USEC_INFINITY-1, USEC_INFINITY-1) == 0);
        assert_se(usec_sub_unsigned(USEC_INFINITY-1, USEC_INFINITY) == 0);
        assert_se(usec_sub_unsigned(USEC_INFINITY, 0) == USEC_INFINITY);
        assert_se(usec_sub_unsigned(USEC_INFINITY, 1) == USEC_INFINITY);
        assert_se(usec_sub_unsigned(USEC_INFINITY, 2) == USEC_INFINITY);
        assert_se(usec_sub_unsigned(USEC_INFINITY, USEC_INFINITY) == USEC_INFINITY);
}

static void test_usec_sub_signed(void) {
        log_info("/* %s */", __func__);

        assert_se(usec_sub_signed(0, 0) == 0);
        assert_se(usec_sub_signed(4, 1) == 3);
        assert_se(usec_sub_signed(4, 4) == 0);
        assert_se(usec_sub_signed(4, 5) == 0);
        assert_se(usec_sub_signed(USEC_INFINITY-3, -3) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY-3, -4) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY-3, -5) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY, 5) == USEC_INFINITY);
}

static void test_format_timestamp(void) {
        unsigned i;

        log_info("/* %s */", __func__);

        for (i = 0; i < 100; i++) {
                char buf[MAX(FORMAT_TIMESTAMP_MAX, FORMAT_TIMESPAN_MAX)];
                usec_t x, y;

                random_bytes(&x, sizeof(x));
                x = x % (2147483600 * USEC_PER_SEC) + 1;

                assert_se(format_timestamp(buf, sizeof(buf), x));
                log_info("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x / USEC_PER_SEC == y / USEC_PER_SEC);

                assert_se(format_timestamp_utc(buf, sizeof(buf), x));
                log_info("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x / USEC_PER_SEC == y / USEC_PER_SEC);

                assert_se(format_timestamp_us(buf, sizeof(buf), x));
                log_info("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x == y);

                assert_se(format_timestamp_us_utc(buf, sizeof(buf), x));
                log_info("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x == y);

                assert_se(format_timestamp_relative(buf, sizeof(buf), x));
                log_info("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);

                /* The two calls above will run with a slightly different local time. Make sure we are in the same
                 * range however, but give enough leeway that this is unlikely to explode. And of course,
                 * format_timestamp_relative() scales the accuracy with the distance from the current time up to one
                 * month, cover for that too. */
                assert_se(y > x ? y - x : x - y <= USEC_PER_MONTH + USEC_PER_DAY);
        }
}

static void test_format_timestamp_utc_one(usec_t val, const char *result) {
        char buf[FORMAT_TIMESTAMP_MAX];
        const char *t;

        t = format_timestamp_utc(buf, sizeof(buf), val);
        assert_se(streq_ptr(t, result));
}

static void test_format_timestamp_utc(void) {
        log_info("/* %s */", __func__);

        test_format_timestamp_utc_one(0, NULL);
        test_format_timestamp_utc_one(1, "Thu 1970-01-01 00:00:00 UTC");
        test_format_timestamp_utc_one(USEC_PER_SEC, "Thu 1970-01-01 00:00:01 UTC");

#if SIZEOF_TIME_T == 8
        test_format_timestamp_utc_one(USEC_TIMESTAMP_FORMATTABLE_MAX, "Thu 9999-12-30 23:59:59 UTC");
        test_format_timestamp_utc_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, "--- XXXX-XX-XX XX:XX:XX");
#elif SIZEOF_TIME_T == 4
        test_format_timestamp_utc_one(USEC_TIMESTAMP_FORMATTABLE_MAX, "Tue 2038-01-19 03:14:07 UTC");
        test_format_timestamp_utc_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, "--- XXXX-XX-XX XX:XX:XX");
#endif

        test_format_timestamp_utc_one(USEC_INFINITY, NULL);
}

static void test_deserialize_dual_timestamp(void) {
        int r;
        dual_timestamp t;

        log_info("/* %s */", __func__);

        r = deserialize_dual_timestamp("1234 5678", &t);
        assert_se(r == 0);
        assert_se(t.realtime == 1234);
        assert_se(t.monotonic == 5678);

        r = deserialize_dual_timestamp("1234x 5678", &t);
        assert_se(r == -EINVAL);

        r = deserialize_dual_timestamp("1234 5678y", &t);
        assert_se(r == -EINVAL);

        r = deserialize_dual_timestamp("-1234 5678", &t);
        assert_se(r == -EINVAL);

        r = deserialize_dual_timestamp("1234 -5678", &t);
        assert_se(r == -EINVAL);

        /* Check that output wasn't modified. */
        assert_se(t.realtime == 1234);
        assert_se(t.monotonic == 5678);

        r = deserialize_dual_timestamp("+123 567", &t);
        assert_se(r == 0);
        assert_se(t.realtime == 123);
        assert_se(t.monotonic == 567);

        /* Check that we get "infinity" on overflow. */
        r = deserialize_dual_timestamp("18446744073709551617 0", &t);
        assert_se(r == 0);
        assert_se(t.realtime == USEC_INFINITY);
        assert_se(t.monotonic == 0);
}

static void assert_similar(usec_t a, usec_t b) {
        usec_t d;

        if (a > b)
                d = a - b;
        else
                d = b - a;

        assert(d < 10*USEC_PER_SEC);
}

static void test_usec_shift_clock(void) {
        usec_t rt, mn, bt;

        log_info("/* %s */", __func__);

        rt = now(CLOCK_REALTIME);
        mn = now(CLOCK_MONOTONIC);
        bt = now(clock_boottime_or_monotonic());

        assert_se(usec_shift_clock(USEC_INFINITY, CLOCK_REALTIME, CLOCK_MONOTONIC) == USEC_INFINITY);

        assert_similar(usec_shift_clock(rt + USEC_PER_HOUR, CLOCK_REALTIME, CLOCK_MONOTONIC), mn + USEC_PER_HOUR);
        assert_similar(usec_shift_clock(rt + 2*USEC_PER_HOUR, CLOCK_REALTIME, clock_boottime_or_monotonic()), bt + 2*USEC_PER_HOUR);
        assert_se(usec_shift_clock(rt + 3*USEC_PER_HOUR, CLOCK_REALTIME, CLOCK_REALTIME_ALARM) == rt + 3*USEC_PER_HOUR);

        assert_similar(usec_shift_clock(mn + 4*USEC_PER_HOUR, CLOCK_MONOTONIC, CLOCK_REALTIME_ALARM), rt + 4*USEC_PER_HOUR);
        assert_similar(usec_shift_clock(mn + 5*USEC_PER_HOUR, CLOCK_MONOTONIC, clock_boottime_or_monotonic()), bt + 5*USEC_PER_HOUR);
        assert_se(usec_shift_clock(mn + 6*USEC_PER_HOUR, CLOCK_MONOTONIC, CLOCK_MONOTONIC) == mn + 6*USEC_PER_HOUR);

        assert_similar(usec_shift_clock(bt + 7*USEC_PER_HOUR, clock_boottime_or_monotonic(), CLOCK_MONOTONIC), mn + 7*USEC_PER_HOUR);
        assert_similar(usec_shift_clock(bt + 8*USEC_PER_HOUR, clock_boottime_or_monotonic(), CLOCK_REALTIME_ALARM), rt + 8*USEC_PER_HOUR);
        assert_se(usec_shift_clock(bt + 9*USEC_PER_HOUR, clock_boottime_or_monotonic(), clock_boottime_or_monotonic()) == bt + 9*USEC_PER_HOUR);

        if (mn > USEC_PER_MINUTE) {
                assert_similar(usec_shift_clock(rt - 30 * USEC_PER_SEC, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC), mn - 30 * USEC_PER_SEC);
                assert_similar(usec_shift_clock(rt - 50 * USEC_PER_SEC, CLOCK_REALTIME, clock_boottime_or_monotonic()), bt - 50 * USEC_PER_SEC);
        }
}

static void test_in_utc_timezone(void) {
        log_info("/* %s */", __func__);

        assert_se(setenv("TZ", ":UTC", 1) >= 0);
        assert_se(in_utc_timezone());
        assert_se(streq(tzname[0], "UTC"));
        assert_se(streq(tzname[1], "UTC"));
        assert_se(timezone == 0);
        assert_se(daylight == 0);

        assert_se(setenv("TZ", "Europe/Berlin", 1) >= 0);
        assert_se(!in_utc_timezone());
        assert_se(streq(tzname[0], "CET"));
        assert_se(streq(tzname[1], "CEST"));

        assert_se(unsetenv("TZ") >= 0);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        log_info("realtime=" USEC_FMT "\n"
                 "monotonic=" USEC_FMT "\n"
                 "boottime=" USEC_FMT "\n",
                 now(CLOCK_REALTIME),
                 now(CLOCK_MONOTONIC),
                 now(clock_boottime_or_monotonic()));

        test_parse_sec();
        test_parse_sec_fix_0();
        test_parse_sec_def_infinity();
        test_parse_time();
        test_parse_nsec();
        test_format_timespan(1);
        test_format_timespan(USEC_PER_MSEC);
        test_format_timespan(USEC_PER_SEC);
        test_timezone_is_valid();
        test_get_timezones();
        test_usec_add();
        test_usec_sub_signed();
        test_usec_sub_unsigned();
        test_format_timestamp();
        test_format_timestamp_utc();
        test_deserialize_dual_timestamp();
        test_usec_shift_clock();
        test_in_utc_timezone();

        /* Ensure time_t is signed */
        assert_cc((time_t) -1 < (time_t) 1);

        /* Ensure TIME_T_MAX works correctly */
        uintmax_t x = TIME_T_MAX;
        x++;
        assert((time_t) x < 0);

        return 0;
}
