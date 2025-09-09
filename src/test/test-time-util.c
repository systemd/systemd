/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "env-util.h"
#include "random-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

#define TRIAL 100u

static void set_timezone(const char *tz) {
        ASSERT_OK(set_unset_env("TZ", tz, /* overwrite = */ true));
        tzset();
        log_info("TZ=%s, tzname[0]=%s, tzname[1]=%s", strna(getenv("TZ")), strempty(tzname[0]), strempty(tzname[1]));
}

TEST(parse_sec) {
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
        assert_se(parse_sec("23us", &u) >= 0);
        assert_se(u == 23);
        assert_se(parse_sec("23μs", &u) >= 0); /* greek small letter mu */
        assert_se(u == 23);
        assert_se(parse_sec("23µs", &u) >= 0); /* micro symbol */
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

TEST(parse_sec_fix_0) {
        usec_t u;

        assert_se(parse_sec_fix_0("5s", &u) >= 0);
        assert_se(u == 5 * USEC_PER_SEC);
        assert_se(parse_sec_fix_0("0s", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec_fix_0("0", &u) >= 0);
        assert_se(u == USEC_INFINITY);
        assert_se(parse_sec_fix_0(" 0", &u) >= 0);
        assert_se(u == USEC_INFINITY);
}

TEST(parse_sec_def_infinity) {
        usec_t u;

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

TEST(parse_time) {
        usec_t u;

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

TEST(parse_nsec) {
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

        log_debug(USEC_FMT"     (at accuracy "USEC_FMT")", x, accuracy);

        assert_se(t = format_timespan(l, sizeof l, x, accuracy));
        log_debug(" = <%s>", t);

        assert_se(parse_sec(t, &y) >= 0);
        log_debug(" = "USEC_FMT, y);

        if (accuracy <= 0)
                accuracy = 1;

        assert_se(x / accuracy == y / accuracy);
}

static void test_format_timespan_accuracy(usec_t accuracy) {
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

TEST(format_timespan) {
        test_format_timespan_accuracy(1);
        test_format_timespan_accuracy(USEC_PER_MSEC);
        test_format_timespan_accuracy(USEC_PER_SEC);

        /* See issue #23928. */
        _cleanup_free_ char *buf = NULL;
        assert_se(buf = new(char, 5));
        assert_se(buf == format_timespan(buf, 5, 100005, 1000));
}

TEST(verify_timezone) {
        assert_se(verify_timezone("Europe/Berlin", LOG_DEBUG) == 0);
        assert_se(verify_timezone("Australia/Sydney", LOG_DEBUG) == 0);
        assert_se(verify_timezone("Europe/Do not exist", LOG_DEBUG) == -EINVAL);
        assert_se(verify_timezone("Europe/DoNotExist", LOG_DEBUG) == -ENOENT);
        assert_se(verify_timezone("/DoNotExist", LOG_DEBUG) == -EINVAL);
        assert_se(verify_timezone("DoNotExist/", LOG_DEBUG) == -EINVAL);
}

TEST(timezone_is_valid) {
        assert_se(timezone_is_valid("Europe/Berlin", LOG_ERR));
        assert_se(timezone_is_valid("Australia/Sydney", LOG_ERR));
        assert_se(!timezone_is_valid("Europe/Do not exist", LOG_ERR));
}

TEST(get_timezones) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;

        r = get_timezones(&zones);
        assert_se(r == 0);

        STRV_FOREACH(zone, zones) {
                r = verify_timezone(*zone, LOG_ERR);
                log_debug_errno(r, "verify_timezone(\"%s\"): %m", *zone);
                assert_se(r >= 0 || r == -ENOENT);
        }
}

TEST(usec_add) {
        assert_se(usec_add(0, 0) == 0);
        assert_se(usec_add(1, 4) == 5);
        assert_se(usec_add(USEC_INFINITY, 5) == USEC_INFINITY);
        assert_se(usec_add(5, USEC_INFINITY) == USEC_INFINITY);
        assert_se(usec_add(USEC_INFINITY-5, 2) == USEC_INFINITY-3);
        assert_se(usec_add(USEC_INFINITY-2, 2) == USEC_INFINITY);
        assert_se(usec_add(USEC_INFINITY-1, 2) == USEC_INFINITY);
        assert_se(usec_add(USEC_INFINITY, 2) == USEC_INFINITY);
}

TEST(usec_sub_unsigned) {
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

TEST(usec_sub_signed) {
        assert_se(usec_sub_signed(0, 0) == 0);
        assert_se(usec_sub_signed(4, 1) == 3);
        assert_se(usec_sub_signed(4, 4) == 0);
        assert_se(usec_sub_signed(4, 5) == 0);

        assert_se(usec_sub_signed(USEC_INFINITY-3, -3) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY-3, -4) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY-3, -5) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY, 5) == USEC_INFINITY);

        assert_se(usec_sub_signed(0, INT64_MAX) == 0);
        assert_se(usec_sub_signed(0, -INT64_MAX) == INT64_MAX);
        assert_se(usec_sub_signed(0, INT64_MIN) == (usec_t) INT64_MAX + 1);
        assert_se(usec_sub_signed(0, -(INT64_MIN+1)) == 0);

        assert_se(usec_sub_signed(USEC_INFINITY, INT64_MAX) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY, -INT64_MAX) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY, INT64_MIN) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY, -(INT64_MIN+1)) == USEC_INFINITY);

        assert_se(usec_sub_signed(USEC_INFINITY-1, INT64_MAX) == USEC_INFINITY-1-INT64_MAX);
        assert_se(usec_sub_signed(USEC_INFINITY-1, -INT64_MAX) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY-1, INT64_MIN) == USEC_INFINITY);
        assert_se(usec_sub_signed(USEC_INFINITY-1, -(INT64_MIN+1)) == USEC_INFINITY-1-((usec_t) (-(INT64_MIN+1))));
}

TEST(format_timestamp) {
        for (unsigned i = 0; i < TRIAL; i++) {
                char buf[CONST_MAX(FORMAT_TIMESTAMP_MAX, FORMAT_TIMESPAN_MAX)];
                usec_t x, y;

                x = random_u64_range(USEC_TIMESTAMP_FORMATTABLE_MAX - USEC_PER_SEC) + USEC_PER_SEC;

                assert_se(format_timestamp(buf, sizeof(buf), x));
                log_debug("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x / USEC_PER_SEC == y / USEC_PER_SEC);

                assert_se(format_timestamp_style(buf, sizeof(buf), x, TIMESTAMP_UNIX));
                log_debug("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x / USEC_PER_SEC == y / USEC_PER_SEC);

                assert_se(format_timestamp_style(buf, sizeof(buf), x, TIMESTAMP_UTC));
                log_debug("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x / USEC_PER_SEC == y / USEC_PER_SEC);

                assert_se(format_timestamp_style(buf, sizeof(buf), x, TIMESTAMP_US));
                log_debug("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x == y);

                assert_se(format_timestamp_style(buf, sizeof(buf), x, TIMESTAMP_US_UTC));
                log_debug("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);
                assert_se(x == y);

                if (x > 2 * USEC_PER_DAY) {
                        assert_se(format_timestamp_style(buf, sizeof(buf), x, TIMESTAMP_DATE));
                        log_debug("%s", buf);
                        assert_se(parse_timestamp(buf, &y) >= 0);
                        assert_se(y > usec_sub_unsigned(x, 2 * USEC_PER_DAY) && y < usec_add(x, 2 * USEC_PER_DAY));
                }

                assert_se(format_timestamp_relative(buf, sizeof(buf), x));
                log_debug("%s", buf);
                assert_se(parse_timestamp(buf, &y) >= 0);

                /* The two calls above will run with a slightly different local time. Make sure we are in the same
                 * range however, but give enough leeway that this is unlikely to explode. And of course,
                 * format_timestamp_relative() scales the accuracy with the distance from the current time up to one
                 * month, cover for that too. */
                assert_se(y > x ? y - x : x - y <= USEC_PER_MONTH + USEC_PER_DAY);
        }
}

static void test_format_timestamp_impl(usec_t x) {
        const char *xx = FORMAT_TIMESTAMP(x);
        ASSERT_NOT_NULL(xx);

#ifndef __GLIBC__
        /* Because of the timezone change, format_timestamp() may set timezone that is currently unused.
         * E.g. Africa/Juba may set EAT, but currently it uses CAT/CAST. */
        const char *space;
        ASSERT_NOT_NULL(space = strrchr(xx, ' '));
        const char *tz = space + 1;
        if (!streq_ptr(tz, tzname[0]) &&
            !streq_ptr(tz, tzname[1]) &&
            parse_gmtoff(tz, NULL) < 0) {

                log_warning("@" USEC_FMT " → %s, timezone '%s' is currently unused, ignoring.", x, xx, tz);

                /* Verify the generated string except for the timezone part. Of course, in most cases, parsed
                 * time does not match with the input, hence only check if it is parsable. */
                ASSERT_OK(parse_timestamp(strndupa_safe(xx, space - xx), NULL));
                return;
        }
#endif

        usec_t y;
        ASSERT_OK(parse_timestamp(xx, &y));
        const char *yy = FORMAT_TIMESTAMP(y);
        ASSERT_NOT_NULL(yy);

        usec_t x_sec = x / USEC_PER_SEC;
        usec_t y_sec = y / USEC_PER_SEC;

        if (x_sec == y_sec && streq(xx, yy))
                return; /* Yay!*/

        /* When the timezone is built with rearguard being enabled (e.g. old Ubuntu and RHEL), the following
         * timezone may provide time shifted 1 hour from the original. See
         * https://github.com/systemd/systemd/issues/28472 and https://github.com/systemd/systemd/pull/35471 */
        bool ignore =
                streq_ptr(getenv("TZ"), "Africa/Windhoek") &&
                (x_sec > y_sec ? x_sec - y_sec : y_sec - x_sec) == 3600;

        log_full(ignore ? LOG_WARNING : LOG_ERR,
                 "@" USEC_FMT " → %s → @" USEC_FMT " → %s%s",
                 x, xx, y, yy,
                 ignore ? ", ignoring." : "");

        ASSERT_TRUE(ignore);
}

static void test_format_timestamp_loop(void) {
        test_format_timestamp_impl(USEC_PER_DAY + USEC_PER_SEC);
        test_format_timestamp_impl(USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT-1);
        test_format_timestamp_impl(USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT);
        test_format_timestamp_impl(USEC_TIMESTAMP_FORMATTABLE_MAX-1);
        test_format_timestamp_impl(USEC_TIMESTAMP_FORMATTABLE_MAX);

        /* Two cases which trigger https://github.com/systemd/systemd/issues/28472 */
        test_format_timestamp_impl(1504938962980066);
        test_format_timestamp_impl(1509482094632752);

        for (unsigned i = 0; i < TRIAL; i++) {
                usec_t x;

                x = random_u64_range(USEC_TIMESTAMP_FORMATTABLE_MAX - USEC_PER_SEC) + USEC_PER_SEC;
                test_format_timestamp_impl(x);
        }
}

TEST(FORMAT_TIMESTAMP) {
        test_format_timestamp_loop();
}

static void test_format_timestamp_with_tz_one(const char *tz) {
        if (!timezone_is_valid(tz, LOG_DEBUG))
                return;

        SAVE_TIMEZONE;
        set_timezone(tz);

        test_format_timestamp_loop();
}

TEST(FORMAT_TIMESTAMP_with_tz) {
        _cleanup_strv_free_ char **timezones = NULL;

        test_format_timestamp_with_tz_one("UTC");

        if (!slow_tests_enabled())
                return (void) log_tests_skipped("slow tests are disabled");

        assert_se(get_timezones(&timezones) >= 0);
        STRV_FOREACH(tz, timezones)
                test_format_timestamp_with_tz_one(*tz);
}

TEST(format_timestamp_relative_full) {
        char buf[CONST_MAX(FORMAT_TIMESTAMP_MAX, FORMAT_TIMESPAN_MAX)];
        usec_t x;

        /* Years and months */
        x = now(CLOCK_REALTIME) - (1*USEC_PER_YEAR + 1*USEC_PER_MONTH);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 year 1 month ago");

        x = now(CLOCK_MONOTONIC) + (1*USEC_PER_YEAR + 1.5*USEC_PER_MONTH);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_MONOTONIC, false));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 year 1 month left");

        x = now(CLOCK_REALTIME) - (1*USEC_PER_YEAR + 2*USEC_PER_MONTH);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 year 2 months ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_YEAR + 1*USEC_PER_MONTH);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 years 1 month ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_YEAR + 2*USEC_PER_MONTH);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 years 2 months ago");

        /* Months and days */
        x = now(CLOCK_REALTIME) - (1*USEC_PER_MONTH + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 month 1 day ago");

        x = now(CLOCK_REALTIME) - (1*USEC_PER_MONTH + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 month 2 days ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_MONTH + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 months 1 day ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_MONTH + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 months 2 days ago");

        /* Weeks and days */
        x = now(CLOCK_REALTIME) - (1*USEC_PER_WEEK + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 week 1 day ago");

        x = now(CLOCK_REALTIME) - (1*USEC_PER_WEEK + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 week 2 days ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_WEEK + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 weeks 1 day ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_WEEK + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative_full(buf, sizeof(buf), x, CLOCK_REALTIME, true));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 weeks 2 days ago");
}

TEST(format_timestamp_relative) {
        char buf[CONST_MAX(FORMAT_TIMESTAMP_MAX, FORMAT_TIMESPAN_MAX)];
        usec_t x;

        /* Only testing timestamps in the past so we don't need to add some delta to account for time passing
         * by while we are running the tests (unless we're running on potatoes and 24 hours somehow passes
         * between our call to now() and format_timestamp_relative's call to now()). */

        /* Years and months */
        x = now(CLOCK_REALTIME) - (1*USEC_PER_YEAR + 1*USEC_PER_MONTH);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 year 1 month ago");

        x = now(CLOCK_REALTIME) - (1*USEC_PER_YEAR + 2*USEC_PER_MONTH);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 year 2 months ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_YEAR + 1*USEC_PER_MONTH);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 years 1 month ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_YEAR + 2*USEC_PER_MONTH);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 years 2 months ago");

        /* Months and days */
        x = now(CLOCK_REALTIME) - (1*USEC_PER_MONTH + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 month 1 day ago");

        x = now(CLOCK_REALTIME) - (1*USEC_PER_MONTH + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 month 2 days ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_MONTH + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 months 1 day ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_MONTH + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 months 2 days ago");

        /* Weeks and days */
        x = now(CLOCK_REALTIME) - (1*USEC_PER_WEEK + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 week 1 day ago");

        x = now(CLOCK_REALTIME) - (1*USEC_PER_WEEK + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "1 week 2 days ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_WEEK + 1*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 weeks 1 day ago");

        x = now(CLOCK_REALTIME) - (2*USEC_PER_WEEK + 2*USEC_PER_DAY);
        assert_se(format_timestamp_relative(buf, sizeof(buf), x));
        log_debug("%s", buf);
        ASSERT_STREQ(buf, "2 weeks 2 days ago");
}

static void test_format_timestamp_one(usec_t val, TimestampStyle style, const char *result) {
        char buf[FORMAT_TIMESTAMP_MAX];
        const char *t;

        t = format_timestamp_style(buf, sizeof(buf), val, style);
        ASSERT_STREQ(t, result);
}

TEST(format_timestamp_range) {
        test_format_timestamp_one(0, TIMESTAMP_UTC, NULL);
        test_format_timestamp_one(0, TIMESTAMP_DATE, NULL);
        test_format_timestamp_one(0, TIMESTAMP_US_UTC, NULL);

        test_format_timestamp_one(1, TIMESTAMP_UTC, "Thu 1970-01-01 00:00:00 UTC");
        test_format_timestamp_one(1, TIMESTAMP_DATE, "Thu 1970-01-01");
        test_format_timestamp_one(1, TIMESTAMP_US_UTC, "Thu 1970-01-01 00:00:00.000001 UTC");

        test_format_timestamp_one(USEC_PER_SEC, TIMESTAMP_UTC, "Thu 1970-01-01 00:00:01 UTC");
        test_format_timestamp_one(USEC_PER_SEC, TIMESTAMP_DATE, "Thu 1970-01-01");
        test_format_timestamp_one(USEC_PER_SEC, TIMESTAMP_US_UTC, "Thu 1970-01-01 00:00:01.000000 UTC");

#if SIZEOF_TIME_T == 8
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX, TIMESTAMP_UTC, "Thu 9999-12-30 23:59:59 UTC");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX, TIMESTAMP_DATE, "Thu 9999-12-30");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, TIMESTAMP_UTC, "--- XXXX-XX-XX XX:XX:XX UTC");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, TIMESTAMP_US_UTC, "--- XXXX-XX-XX XX:XX:XX.XXXXXX UTC");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, TIMESTAMP_DATE, "--- XXXX-XX-XX");
#elif SIZEOF_TIME_T == 4
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX, TIMESTAMP_UTC, "Mon 2038-01-18 03:14:07 UTC");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX, TIMESTAMP_DATE, "Mon 2038-01-18");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, TIMESTAMP_UTC, "--- XXXX-XX-XX XX:XX:XX UTC");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, TIMESTAMP_US_UTC, "--- XXXX-XX-XX XX:XX:XX.XXXXXX UTC");
        test_format_timestamp_one(USEC_TIMESTAMP_FORMATTABLE_MAX + 1, TIMESTAMP_DATE, "--- XXXX-XX-XX");
#endif

        test_format_timestamp_one(USEC_INFINITY, TIMESTAMP_UTC, NULL);
}

TEST(parse_gmtoff) {
        long t;

        ASSERT_OK(parse_gmtoff("+14", &t));
        ASSERT_EQ(t, (long) (14 * USEC_PER_HOUR / USEC_PER_SEC));
        ASSERT_OK(parse_gmtoff("-09", &t));
        ASSERT_EQ(t, - (long) (9 * USEC_PER_HOUR / USEC_PER_SEC));
        ASSERT_OK(parse_gmtoff("+1400", &t));
        ASSERT_EQ(t, (long) (14 * USEC_PER_HOUR / USEC_PER_SEC));
        ASSERT_OK(parse_gmtoff("-0900", &t));
        ASSERT_EQ(t, - (long) (9 * USEC_PER_HOUR / USEC_PER_SEC));
        ASSERT_OK(parse_gmtoff("+14:00", &t));
        ASSERT_EQ(t, (long) (14 * USEC_PER_HOUR / USEC_PER_SEC));
        ASSERT_OK(parse_gmtoff("-09:00", &t));
        ASSERT_EQ(t, - (long) (9 * USEC_PER_HOUR / USEC_PER_SEC));

        ASSERT_ERROR(parse_gmtoff("", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("UTC", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("09", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("0900", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("?0900", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("?0900", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("+0900abc", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("+0900 ", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("+090000", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("+0900:00", &t), EINVAL);
        ASSERT_ERROR(parse_gmtoff("+0900.00", &t), EINVAL);
}

static void test_parse_timestamp_one(const char *str, usec_t max_diff, usec_t expected) {
        usec_t usec = USEC_INFINITY;
        int r;

        r = parse_timestamp(str, &usec);
        log_debug("/* %s(%s): max_diff="USEC_FMT", expected="USEC_FMT", result="USEC_FMT" */", __func__, str, max_diff, expected, usec);
        assert_se(r >= 0);
        assert_se(usec >= expected);
        assert_se(usec_sub_unsigned(usec, expected) <= max_diff);
}

static bool time_is_zero(usec_t usec) {
        const char *s;

        s = FORMAT_TIMESTAMP(usec);
        return strstr(s, " 00:00:00 ");
}

static bool timezone_equal(usec_t today, usec_t target) {
        const char *s, *t, *sz, *tz;

        s = FORMAT_TIMESTAMP(today);
        t = FORMAT_TIMESTAMP(target);
        assert_se(sz = strrchr(s, ' '));
        assert_se(tz = strrchr(t, ' '));
        log_debug("%s("USEC_FMT", "USEC_FMT") -> %s, %s", __func__, today, target, s, t);
        return streq(sz, tz);
}

static void test_parse_timestamp_impl(const char *tz) {
        usec_t today, today2, now_usec;

        /* Invalid: Ensure that systemctl reboot --when=show and --when=cancel
         * will not result in ambiguities */
        assert_se(parse_timestamp("show", NULL) == -EINVAL);
        assert_se(parse_timestamp("cancel", NULL) == -EINVAL);

        /* UTC */
        test_parse_timestamp_one("Thu 1970-01-01 00:01 UTC", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Thu 1970-01-01 00:00:01 UTC", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Thu 1970-01-01 00:00:01.001 UTC", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Thu 1970-01-01 00:00:01.0010 UTC", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("Thu 70-01-01 00:01 UTC", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Thu 70-01-01 00:00:01 UTC", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Thu 70-01-01 00:00:01.001 UTC", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Thu 70-01-01 00:00:01.0010 UTC", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("1970-01-01 00:01 UTC", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("1970-01-01 00:00:01 UTC", 0, USEC_PER_SEC);
        test_parse_timestamp_one("1970-01-01 00:00:01.001 UTC", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("1970-01-01 00:00:01.0010 UTC", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("70-01-01 00:01 UTC", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("70-01-01 00:00:01 UTC", 0, USEC_PER_SEC);
        test_parse_timestamp_one("70-01-01 00:00:01.001 UTC", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("70-01-01 00:00:01.0010 UTC", 0, USEC_PER_SEC + 1000);

        /* Examples from RFC3339 */
        test_parse_timestamp_one("1985-04-12T23:20:50.52Z", 0, 482196050 * USEC_PER_SEC + 520000);
        test_parse_timestamp_one("1996-12-19T16:39:57-08:00", 0, 851042397 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("1996-12-20T00:39:57Z", 0, 851042397 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("1990-12-31T23:59:60Z", 0, 662688000 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("1990-12-31T15:59:60-08:00", 0, 662688000 * USEC_PER_SEC + 000000);
        assert_se(parse_timestamp("1937-01-01T12:00:27.87+00:20", NULL) == -ERANGE); /* we don't support pre-epoch timestamps */
        /* We accept timestamps without seconds as well */
        test_parse_timestamp_one("1996-12-20T00:39Z", 0, (851042397 - 57) * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("1990-12-31T15:59-08:00", 0, (662688000-60) * USEC_PER_SEC + 000000);
        /* We drop day-of-week before parsing the timestamp */
        test_parse_timestamp_one("Thu 1970-01-01T00:01 UTC", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Thu 1970-01-01T00:00:01 UTC", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Thu 1970-01-01T00:01Z", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Thu 1970-01-01T00:00:01Z", 0, USEC_PER_SEC);
        /* RFC3339-style timezones can be welded to all formats */
        assert_se(parse_timestamp("today UTC", &today) == 0);
        assert_se(parse_timestamp("todayZ", &today2) == 0);
        assert_se(today == today2);
        assert_se(parse_timestamp("today +0200", &today) == 0);
        assert_se(parse_timestamp("today+02:00", &today2) == 0);
        assert_se(today == today2);

        /* https://ijmacd.github.io/rfc3339-iso8601/ */
        test_parse_timestamp_one("2023-09-06 12:49:27-00:00", 0, 1694004567 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("2023-09-06 12:49:27.284-00:00", 0, 1694004567 * USEC_PER_SEC + 284000);
        test_parse_timestamp_one("2023-09-06 12:49:27.284029Z", 0, 1694004567 * USEC_PER_SEC + 284029);
        test_parse_timestamp_one("2023-09-06 12:49:27.284Z", 0, 1694004567 * USEC_PER_SEC + 284000);
        test_parse_timestamp_one("2023-09-06 12:49:27.28Z", 0, 1694004567 * USEC_PER_SEC + 280000);
        test_parse_timestamp_one("2023-09-06 12:49:27.2Z", 0, 1694004567 * USEC_PER_SEC + 200000);
        test_parse_timestamp_one("2023-09-06 12:49:27Z", 0, 1694004567 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("2023-09-06 14:49:27+02:00", 0, 1694004567 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("2023-09-06 14:49:27.2+02:00", 0, 1694004567 * USEC_PER_SEC + 200000);
        test_parse_timestamp_one("2023-09-06 14:49:27.28+02:00", 0, 1694004567 * USEC_PER_SEC + 280000);
        test_parse_timestamp_one("2023-09-06 14:49:27.284+02:00", 0, 1694004567 * USEC_PER_SEC + 284000);
        test_parse_timestamp_one("2023-09-06 14:49:27.284029+02:00", 0, 1694004567 * USEC_PER_SEC + 284029);
        test_parse_timestamp_one("2023-09-06T12:49:27+00:00", 0, 1694004567 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("2023-09-06T12:49:27-00:00", 0, 1694004567 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("2023-09-06T12:49:27.284+00:00", 0, 1694004567 * USEC_PER_SEC + 284000);
        test_parse_timestamp_one("2023-09-06T12:49:27.284-00:00", 0, 1694004567 * USEC_PER_SEC + 284000);
        test_parse_timestamp_one("2023-09-06T12:49:27.284029Z", 0, 1694004567 * USEC_PER_SEC + 284029);
        test_parse_timestamp_one("2023-09-06T12:49:27.284Z", 0, 1694004567 * USEC_PER_SEC + 284000);
        test_parse_timestamp_one("2023-09-06T12:49:27.28Z", 0, 1694004567 * USEC_PER_SEC + 280000);
        test_parse_timestamp_one("2023-09-06T12:49:27.2Z", 0, 1694004567 * USEC_PER_SEC + 200000);
        test_parse_timestamp_one("2023-09-06T12:49:27Z", 0, 1694004567 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("2023-09-06T14:49:27+02:00", 0, 1694004567 * USEC_PER_SEC + 000000);
        test_parse_timestamp_one("2023-09-06T14:49:27.284+02:00", 0, 1694004567 * USEC_PER_SEC + 284000);
        test_parse_timestamp_one("2023-09-06T14:49:27.284029+02:00", 0, 1694004567 * USEC_PER_SEC + 284029);
        test_parse_timestamp_one("2023-09-06T21:34:27+08:45", 0, 1694004567 * USEC_PER_SEC + 000000);

        if (timezone_is_valid("Asia/Tokyo", LOG_DEBUG)) {
                /* Asia/Tokyo (+0900) */
                test_parse_timestamp_one("Thu 1970-01-01 09:01 Asia/Tokyo", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Thu 1970-01-01 09:00:01 Asia/Tokyo", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Thu 1970-01-01 09:00:01.001 Asia/Tokyo", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Thu 1970-01-01 09:00:01.0010 Asia/Tokyo", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("Thu 70-01-01 09:01 Asia/Tokyo", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Thu 70-01-01 09:00:01 Asia/Tokyo", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Thu 70-01-01 09:00:01.001 Asia/Tokyo", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Thu 70-01-01 09:00:01.0010 Asia/Tokyo", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("1970-01-01 09:01 Asia/Tokyo", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("1970-01-01 09:00:01 Asia/Tokyo", 0, USEC_PER_SEC);
                test_parse_timestamp_one("1970-01-01 09:00:01.001 Asia/Tokyo", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("1970-01-01 09:00:01.0010 Asia/Tokyo", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("70-01-01 09:01 Asia/Tokyo", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("70-01-01 09:00:01 Asia/Tokyo", 0, USEC_PER_SEC);
                test_parse_timestamp_one("70-01-01 09:00:01.001 Asia/Tokyo", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("70-01-01 09:00:01.0010 Asia/Tokyo", 0, USEC_PER_SEC + 1000);
        }

        if (streq_ptr(tz, "Asia/Tokyo")) {
                /* JST (+0900) */
                test_parse_timestamp_one("Thu 1970-01-01 09:01 JST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Thu 1970-01-01 09:00:01 JST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Thu 1970-01-01 09:00:01.001 JST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Thu 1970-01-01 09:00:01.0010 JST", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("Thu 70-01-01 09:01 JST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Thu 70-01-01 09:00:01 JST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Thu 70-01-01 09:00:01.001 JST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Thu 70-01-01 09:00:01.0010 JST", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("1970-01-01 09:01 JST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("1970-01-01 09:00:01 JST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("1970-01-01 09:00:01.001 JST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("1970-01-01 09:00:01.0010 JST", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("70-01-01 09:01 JST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("70-01-01 09:00:01 JST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("70-01-01 09:00:01.001 JST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("70-01-01 09:00:01.0010 JST", 0, USEC_PER_SEC + 1000);
        }

        if (timezone_is_valid("America/New_York", LOG_DEBUG)) {
                /* America/New_York (-0500) */
                test_parse_timestamp_one("Wed 1969-12-31 19:01 America/New_York", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Wed 1969-12-31 19:00:01 America/New_York", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Wed 1969-12-31 19:00:01.001 America/New_York", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Wed 1969-12-31 19:00:01.0010 America/New_York", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("Wed 69-12-31 19:01 America/New_York", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Wed 69-12-31 19:00:01 America/New_York", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Wed 69-12-31 19:00:01.001 America/New_York", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Wed 69-12-31 19:00:01.0010 America/New_York", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("1969-12-31 19:01 America/New_York", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("1969-12-31 19:00:01 America/New_York", 0, USEC_PER_SEC);
                test_parse_timestamp_one("1969-12-31 19:00:01.001 America/New_York", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("1969-12-31 19:00:01.0010 America/New_York", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("69-12-31 19:01 America/New_York", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("69-12-31 19:00:01 America/New_York", 0, USEC_PER_SEC);
                test_parse_timestamp_one("69-12-31 19:00:01.001 America/New_York", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("69-12-31 19:00:01.0010 America/New_York", 0, USEC_PER_SEC + 1000);
        }

        if (streq_ptr(tz, "America/New_York")) {
                /* EST (-0500) */
                test_parse_timestamp_one("Wed 1969-12-31 19:01 EST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Wed 1969-12-31 19:00:01 EST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Wed 1969-12-31 19:00:01.001 EST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Wed 1969-12-31 19:00:01.0010 EST", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("Wed 69-12-31 19:01 EST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Wed 69-12-31 19:00:01 EST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Wed 69-12-31 19:00:01.001 EST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Wed 69-12-31 19:00:01.0010 EST", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("1969-12-31 19:01 EST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("1969-12-31 19:00:01 EST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("1969-12-31 19:00:01.001 EST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("1969-12-31 19:00:01.0010 EST", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("69-12-31 19:01 EST", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("69-12-31 19:00:01 EST", 0, USEC_PER_SEC);
                test_parse_timestamp_one("69-12-31 19:00:01.001 EST", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("69-12-31 19:00:01.0010 EST", 0, USEC_PER_SEC + 1000);
        }

        if (timezone_is_valid("NZ", LOG_DEBUG)) {
                /* NZ (+1200) */
                test_parse_timestamp_one("Thu 1970-01-01 12:01 NZ", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Thu 1970-01-01 12:00:01 NZ", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Thu 1970-01-01 12:00:01.001 NZ", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Thu 1970-01-01 12:00:01.0010 NZ", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("Thu 70-01-01 12:01 NZ", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("Thu 70-01-01 12:00:01 NZ", 0, USEC_PER_SEC);
                test_parse_timestamp_one("Thu 70-01-01 12:00:01.001 NZ", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("Thu 70-01-01 12:00:01.0010 NZ", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("1970-01-01 12:01 NZ", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("1970-01-01 12:00:01 NZ", 0, USEC_PER_SEC);
                test_parse_timestamp_one("1970-01-01 12:00:01.001 NZ", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("1970-01-01 12:00:01.0010 NZ", 0, USEC_PER_SEC + 1000);

                test_parse_timestamp_one("70-01-01 12:01 NZ", 0, USEC_PER_MINUTE);
                test_parse_timestamp_one("70-01-01 12:00:01 NZ", 0, USEC_PER_SEC);
                test_parse_timestamp_one("70-01-01 12:00:01.001 NZ", 0, USEC_PER_SEC + 1000);
                test_parse_timestamp_one("70-01-01 12:00:01.0010 NZ", 0, USEC_PER_SEC + 1000);
        }

        /* -06 */
        test_parse_timestamp_one("Wed 1969-12-31 18:01 -06", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01 -06", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01.001 -06", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01.0010 -06", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("Wed 69-12-31 18:01 -06", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01 -06", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01.001 -06", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01.0010 -06", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("1969-12-31 18:01 -06", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("1969-12-31 18:00:01 -06", 0, USEC_PER_SEC);
        test_parse_timestamp_one("1969-12-31 18:00:01.001 -06", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("1969-12-31 18:00:01.0010 -06", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("69-12-31 18:01 -06", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("69-12-31 18:00:01 -06", 0, USEC_PER_SEC);
        test_parse_timestamp_one("69-12-31 18:00:01.001 -06", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("69-12-31 18:00:01.0010 -06", 0, USEC_PER_SEC + 1000);

        /* -0600 */
        test_parse_timestamp_one("Wed 1969-12-31 18:01 -0600", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01 -0600", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01.001 -0600", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01.0010 -0600", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("Wed 69-12-31 18:01 -0600", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01 -0600", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01.001 -0600", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01.0010 -0600", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("1969-12-31 18:01 -0600", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("1969-12-31 18:00:01 -0600", 0, USEC_PER_SEC);
        test_parse_timestamp_one("1969-12-31 18:00:01.001 -0600", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("1969-12-31 18:00:01.0010 -0600", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("69-12-31 18:01 -0600", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("69-12-31 18:00:01 -0600", 0, USEC_PER_SEC);
        test_parse_timestamp_one("69-12-31 18:00:01.001 -0600", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("69-12-31 18:00:01.0010 -0600", 0, USEC_PER_SEC + 1000);

        /* -06:00 */
        test_parse_timestamp_one("Wed 1969-12-31 18:01 -06:00", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01 -06:00", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01.001 -06:00", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Wed 1969-12-31 18:00:01.0010 -06:00", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("Wed 69-12-31 18:01 -06:00", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01 -06:00", 0, USEC_PER_SEC);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01.001 -06:00", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("Wed 69-12-31 18:00:01.0010 -06:00", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("1969-12-31 18:01 -06:00", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("1969-12-31 18:00:01 -06:00", 0, USEC_PER_SEC);
        test_parse_timestamp_one("1969-12-31 18:00:01.001 -06:00", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("1969-12-31 18:00:01.0010 -06:00", 0, USEC_PER_SEC + 1000);

        test_parse_timestamp_one("69-12-31 18:01 -06:00", 0, USEC_PER_MINUTE);
        test_parse_timestamp_one("69-12-31 18:00:01 -06:00", 0, USEC_PER_SEC);
        test_parse_timestamp_one("69-12-31 18:00:01.001 -06:00", 0, USEC_PER_SEC + 1000);
        test_parse_timestamp_one("69-12-31 18:00:01.0010 -06:00", 0, USEC_PER_SEC + 1000);

        /* without date */
        assert_se(parse_timestamp("today", &today) == 0);
        if (time_is_zero(today)) {
                test_parse_timestamp_one("00:01", 0, today + USEC_PER_MINUTE);
                test_parse_timestamp_one("00:00:01", 0, today + USEC_PER_SEC);
                test_parse_timestamp_one("00:00:01.001", 0, today + USEC_PER_SEC + 1000);
                test_parse_timestamp_one("00:00:01.0010", 0, today + USEC_PER_SEC + 1000);

                if (timezone_equal(today, today + USEC_PER_DAY) && time_is_zero(today + USEC_PER_DAY))
                        test_parse_timestamp_one("tomorrow", 0, today + USEC_PER_DAY);
                if (timezone_equal(today, today - USEC_PER_DAY) && time_is_zero(today - USEC_PER_DAY))
                        test_parse_timestamp_one("yesterday", 0, today - USEC_PER_DAY);
        }

        /* with timezone */
        if (tz) {
                _cleanup_free_ char *s = NULL;

                ASSERT_NOT_NULL((s = strjoin("Fri 2012-11-23 23:02:15 ", tz)));
                ASSERT_OK(parse_timestamp(s, NULL));
        }

        /* relative */
        assert_se(parse_timestamp("now", &now_usec) == 0);
        test_parse_timestamp_one("+5hours", USEC_PER_MINUTE, now_usec + 5 * USEC_PER_HOUR);
        if (now_usec >= 10 * USEC_PER_DAY)
                test_parse_timestamp_one("-10days", USEC_PER_MINUTE, now_usec - 10 * USEC_PER_DAY);
        test_parse_timestamp_one("2weeks left", USEC_PER_MINUTE, now_usec + 2 * USEC_PER_WEEK);
        if (now_usec >= 30 * USEC_PER_MINUTE)
                test_parse_timestamp_one("30minutes ago", USEC_PER_MINUTE, now_usec - 30 * USEC_PER_MINUTE);
}

TEST(parse_timestamp) {
        test_parse_timestamp_impl(NULL);
}

static void test_parse_timestamp_with_tz_one(const char *tz) {
        if (!timezone_is_valid(tz, LOG_DEBUG))
                return;

        SAVE_TIMEZONE;
        set_timezone(tz);

        test_parse_timestamp_impl(tz);
}

TEST(parse_timestamp_with_tz) {
        _cleanup_strv_free_ char **timezones = NULL;

        test_parse_timestamp_with_tz_one("UTC");

        if (!slow_tests_enabled())
                return (void) log_tests_skipped("slow tests are disabled");

        assert_se(get_timezones(&timezones) >= 0);
        STRV_FOREACH(tz, timezones)
                test_parse_timestamp_with_tz_one(*tz);
}

TEST(deserialize_dual_timestamp) {
        int r;
        dual_timestamp t;

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

        assert_se(d < 10*USEC_PER_SEC);
}

TEST(usec_shift_clock) {
        usec_t rt, mn, bt;

        rt = now(CLOCK_REALTIME);
        mn = now(CLOCK_MONOTONIC);
        bt = now(CLOCK_BOOTTIME);

        assert_se(usec_shift_clock(USEC_INFINITY, CLOCK_REALTIME, CLOCK_MONOTONIC) == USEC_INFINITY);

        assert_similar(usec_shift_clock(rt + USEC_PER_HOUR, CLOCK_REALTIME, CLOCK_MONOTONIC), mn + USEC_PER_HOUR);
        assert_similar(usec_shift_clock(rt + 2*USEC_PER_HOUR, CLOCK_REALTIME, CLOCK_BOOTTIME), bt + 2*USEC_PER_HOUR);
        assert_se(usec_shift_clock(rt + 3*USEC_PER_HOUR, CLOCK_REALTIME, CLOCK_REALTIME_ALARM) == rt + 3*USEC_PER_HOUR);

        assert_similar(usec_shift_clock(mn + 4*USEC_PER_HOUR, CLOCK_MONOTONIC, CLOCK_REALTIME_ALARM), rt + 4*USEC_PER_HOUR);
        assert_similar(usec_shift_clock(mn + 5*USEC_PER_HOUR, CLOCK_MONOTONIC, CLOCK_BOOTTIME), bt + 5*USEC_PER_HOUR);
        assert_se(usec_shift_clock(mn + 6*USEC_PER_HOUR, CLOCK_MONOTONIC, CLOCK_MONOTONIC) == mn + 6*USEC_PER_HOUR);

        assert_similar(usec_shift_clock(bt + 7*USEC_PER_HOUR, CLOCK_BOOTTIME, CLOCK_MONOTONIC), mn + 7*USEC_PER_HOUR);
        assert_similar(usec_shift_clock(bt + 8*USEC_PER_HOUR, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM), rt + 8*USEC_PER_HOUR);
        assert_se(usec_shift_clock(bt + 9*USEC_PER_HOUR, CLOCK_BOOTTIME, CLOCK_BOOTTIME) == bt + 9*USEC_PER_HOUR);

        if (mn > USEC_PER_MINUTE) {
                assert_similar(usec_shift_clock(rt - 30 * USEC_PER_SEC, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC), mn - 30 * USEC_PER_SEC);
                assert_similar(usec_shift_clock(rt - 50 * USEC_PER_SEC, CLOCK_REALTIME, CLOCK_BOOTTIME), bt - 50 * USEC_PER_SEC);
        }
}

TEST(in_utc_timezone) {
        SAVE_TIMEZONE;

        assert_se(setenv("TZ", "UTC", 1) >= 0);
        assert_se(in_utc_timezone());
        ASSERT_STREQ(tzname[0], "UTC");
#ifdef __GLIBC__
        ASSERT_STREQ(tzname[1], "UTC");
#else
        /* musl sets an empty string to tzname[1] when DST is not used by the timezone. */
        ASSERT_STREQ(tzname[1], "");
#endif
        assert_se(timezone == 0);
        assert_se(daylight == 0);

        assert_se(setenv("TZ", "Europe/Berlin", 1) >= 0);
        assert_se(!in_utc_timezone());
        ASSERT_STREQ(tzname[0], "CET");
        ASSERT_STREQ(tzname[1], "CEST");
}

TEST(map_clock_usec) {
        usec_t nowr, x, y, z;

        x = nowr = now(CLOCK_REALTIME); /* right now */
        y = map_clock_usec(x, CLOCK_REALTIME, CLOCK_MONOTONIC);
        z = map_clock_usec(y, CLOCK_MONOTONIC, CLOCK_REALTIME);
        /* Converting forth and back will introduce inaccuracies, since we cannot query both clocks atomically, but it should be small. Even on the slowest CI smaller than 1h */

        assert_se((z > x ? z - x : x - z) < USEC_PER_HOUR);

        assert_se(nowr < USEC_INFINITY - USEC_PER_DAY*7); /* overflow check */
        x = nowr + USEC_PER_DAY*7; /* 1 week from now */
        y = map_clock_usec(x, CLOCK_REALTIME, CLOCK_MONOTONIC);
        assert_se(timestamp_is_set(y));
        z = map_clock_usec(y, CLOCK_MONOTONIC, CLOCK_REALTIME);
        assert_se(timestamp_is_set(z));
        assert_se((z > x ? z - x : x - z) < USEC_PER_HOUR);

        assert_se(nowr > USEC_PER_DAY * 7); /* underflow check */
        x = nowr - USEC_PER_DAY*7; /* 1 week ago */
        y = map_clock_usec(x, CLOCK_REALTIME, CLOCK_MONOTONIC);
        if (y != 0) { /* might underflow if machine is not up long enough for the monotonic clock to be beyond 1w */
                assert_se(y < USEC_INFINITY);
                z = map_clock_usec(y, CLOCK_MONOTONIC, CLOCK_REALTIME);
                assert_se(timestamp_is_set(z));
                assert_se((z > x ? z - x : x - z) < USEC_PER_HOUR);
        }
}

static void test_timezone_offset_change_one(const char *utc, const char *pretty) {
        usec_t x, y, z;
        char *s;

        assert_se(parse_timestamp(utc, &x) >= 0);

        s = FORMAT_TIMESTAMP_STYLE(x, TIMESTAMP_UTC);
        assert_se(parse_timestamp(s, &y) >= 0);
        log_debug("%s -> " USEC_FMT " -> %s -> " USEC_FMT, utc, x, s, y);
        ASSERT_STREQ(s, utc);
        assert_se(x == y);

        assert_se(parse_timestamp(pretty, &y) >= 0);
        s = FORMAT_TIMESTAMP_STYLE(y, TIMESTAMP_PRETTY);
        assert_se(parse_timestamp(s, &z) >= 0);
        log_debug("%s -> " USEC_FMT " -> %s -> " USEC_FMT, pretty, y, s, z);
        ASSERT_STREQ(s, pretty);
        assert_se(x == y);
        assert_se(x == z);
}

TEST(timezone_offset_change) {
        SAVE_TIMEZONE;

        /* See issue #26370. */

        if (timezone_is_valid("Africa/Casablanca", LOG_DEBUG)) {
                set_timezone("Africa/Casablanca");

                test_timezone_offset_change_one("Sun 2015-10-25 01:59:59 UTC", "Sun 2015-10-25 02:59:59 +01");
                test_timezone_offset_change_one("Sun 2015-10-25 02:00:00 UTC", "Sun 2015-10-25 02:00:00 +00");
                test_timezone_offset_change_one("Sun 2018-06-17 01:59:59 UTC", "Sun 2018-06-17 01:59:59 +00");
                test_timezone_offset_change_one("Sun 2018-06-17 02:00:00 UTC", "Sun 2018-06-17 03:00:00 +01");
                test_timezone_offset_change_one("Sun 2018-10-28 01:59:59 UTC", "Sun 2018-10-28 02:59:59 +01");
                test_timezone_offset_change_one("Sun 2018-10-28 02:00:00 UTC", "Sun 2018-10-28 03:00:00 +01");
        }

        if (timezone_is_valid("Asia/Atyrau", LOG_DEBUG)) {
                set_timezone("Asia/Atyrau");

                test_timezone_offset_change_one("Sat 2004-03-27 21:59:59 UTC", "Sun 2004-03-28 01:59:59 +04");
                test_timezone_offset_change_one("Sat 2004-03-27 22:00:00 UTC", "Sun 2004-03-28 03:00:00 +05");
                test_timezone_offset_change_one("Sat 2004-10-30 21:59:59 UTC", "Sun 2004-10-31 02:59:59 +05");
                test_timezone_offset_change_one("Sat 2004-10-30 22:00:00 UTC", "Sun 2004-10-31 03:00:00 +05");
        }

        if (timezone_is_valid("Chile/EasterIsland", LOG_DEBUG)) {
                set_timezone("Chile/EasterIsland");

                test_timezone_offset_change_one("Sun 1981-10-11 03:59:59 UTC", "Sat 1981-10-10 20:59:59 -07");
                test_timezone_offset_change_one("Sun 1981-10-11 04:00:00 UTC", "Sat 1981-10-10 22:00:00 -06");
                test_timezone_offset_change_one("Sun 1982-03-14 02:59:59 UTC", "Sat 1982-03-13 20:59:59 -06");
                test_timezone_offset_change_one("Sun 1982-03-14 03:00:00 UTC", "Sat 1982-03-13 21:00:00 -06");
        }
}

static usec_t absdiff(usec_t a, usec_t b) {
        return a > b ? a - b : b - a;
}

TEST(mktime_or_timegm_usec) {

        usec_t n = now(CLOCK_REALTIME), m;
        struct tm tm;

        assert_se(localtime_or_gmtime_usec(n, /* utc= */ false, &tm) >= 0);
        assert_se(mktime_or_timegm_usec(&tm, /* utc= */ false, &m) >= 0);
        assert_se(absdiff(n, m) < 2 * USEC_PER_DAY);

        assert_se(localtime_or_gmtime_usec(n, /* utc= */ true, &tm) >= 0);
        assert_se(mktime_or_timegm_usec(&tm, /* utc= */ true, &m) >= 0);
        assert_se(absdiff(n, m) < USEC_PER_SEC);

        /* This definitely should fail, because we refuse dates before the UNIX epoch */
        tm = (struct tm) {
                .tm_mday = 15,
                .tm_mon = 11,
                .tm_year = 1969 - 1900,
        };

        assert_se(mktime_or_timegm_usec(&tm, /* utc= */ true, NULL) == -ERANGE);
}

static int intro(void) {
        /* Tests have hard-coded results that do not expect a specific timezone to be set by the caller */
        assert_se(unsetenv("TZ") >= 0);

        log_info("realtime=" USEC_FMT "\n"
                 "monotonic=" USEC_FMT "\n"
                 "boottime=" USEC_FMT "\n",
                 now(CLOCK_REALTIME),
                 now(CLOCK_MONOTONIC),
                 now(CLOCK_BOOTTIME));

        /* Ensure time_t is signed */
        assert_cc((time_t) -1 < (time_t) 1);

        /* Ensure TIME_T_MAX works correctly */
        uintmax_t x = TIME_T_MAX;
        x++;
        assert_se((time_t) x < 0);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
