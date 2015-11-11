/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Thomas H.P. Andersen

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

#include <locale.h>
#include <math.h>

#include "log.h"
#include "parse-util.h"

static void test_parse_boolean(void) {
        assert_se(parse_boolean("1") == 1);
        assert_se(parse_boolean("y") == 1);
        assert_se(parse_boolean("Y") == 1);
        assert_se(parse_boolean("yes") == 1);
        assert_se(parse_boolean("YES") == 1);
        assert_se(parse_boolean("true") == 1);
        assert_se(parse_boolean("TRUE") == 1);
        assert_se(parse_boolean("on") == 1);
        assert_se(parse_boolean("ON") == 1);

        assert_se(parse_boolean("0") == 0);
        assert_se(parse_boolean("n") == 0);
        assert_se(parse_boolean("N") == 0);
        assert_se(parse_boolean("no") == 0);
        assert_se(parse_boolean("NO") == 0);
        assert_se(parse_boolean("false") == 0);
        assert_se(parse_boolean("FALSE") == 0);
        assert_se(parse_boolean("off") == 0);
        assert_se(parse_boolean("OFF") == 0);

        assert_se(parse_boolean("garbage") < 0);
        assert_se(parse_boolean("") < 0);
        assert_se(parse_boolean("full") < 0);
}

static void test_parse_pid(void) {
        int r;
        pid_t pid;

        r = parse_pid("100", &pid);
        assert_se(r == 0);
        assert_se(pid == 100);

        r = parse_pid("0x7FFFFFFF", &pid);
        assert_se(r == 0);
        assert_se(pid == 2147483647);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        r = parse_pid("0", &pid);
        assert_se(r == -ERANGE);
        assert_se(pid == 65);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        r = parse_pid("-100", &pid);
        assert_se(r == -ERANGE);
        assert_se(pid == 65);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        r = parse_pid("0xFFFFFFFFFFFFFFFFF", &pid);
        assert_se(r == -ERANGE);
        assert_se(pid == 65);

        r = parse_pid("junk", &pid);
        assert_se(r == -EINVAL);
}

static void test_parse_mode(void) {
        mode_t m;

        assert_se(parse_mode("-1", &m) < 0);
        assert_se(parse_mode("", &m) < 0);
        assert_se(parse_mode("888", &m) < 0);
        assert_se(parse_mode("77777", &m) < 0);

        assert_se(parse_mode("544", &m) >= 0 && m == 0544);
        assert_se(parse_mode("777", &m) >= 0 && m == 0777);
        assert_se(parse_mode("7777", &m) >= 0 && m == 07777);
        assert_se(parse_mode("0", &m) >= 0 && m == 0);
}

static void test_parse_size(void) {
        uint64_t bytes;

        assert_se(parse_size("111", 1024, &bytes) == 0);
        assert_se(bytes == 111);

        assert_se(parse_size("111.4", 1024, &bytes) == 0);
        assert_se(bytes == 111);

        assert_se(parse_size(" 112 B", 1024, &bytes) == 0);
        assert_se(bytes == 112);

        assert_se(parse_size(" 112.6 B", 1024, &bytes) == 0);
        assert_se(bytes == 112);

        assert_se(parse_size("3.5 K", 1024, &bytes) == 0);
        assert_se(bytes == 3*1024 + 512);

        assert_se(parse_size("3. K", 1024, &bytes) == 0);
        assert_se(bytes == 3*1024);

        assert_se(parse_size("3.0 K", 1024, &bytes) == 0);
        assert_se(bytes == 3*1024);

        assert_se(parse_size("3. 0 K", 1024, &bytes) == -EINVAL);

        assert_se(parse_size(" 4 M 11.5K", 1024, &bytes) == 0);
        assert_se(bytes == 4*1024*1024 + 11 * 1024 + 512);

        assert_se(parse_size("3B3.5G", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("3.5G3B", 1024, &bytes) == 0);
        assert_se(bytes == 3ULL*1024*1024*1024 + 512*1024*1024 + 3);

        assert_se(parse_size("3.5G 4B", 1024, &bytes) == 0);
        assert_se(bytes == 3ULL*1024*1024*1024 + 512*1024*1024 + 4);

        assert_se(parse_size("3B3G4T", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("4T3G3B", 1024, &bytes) == 0);
        assert_se(bytes == (4ULL*1024 + 3)*1024*1024*1024 + 3);

        assert_se(parse_size(" 4 T 3 G 3 B", 1024, &bytes) == 0);
        assert_se(bytes == (4ULL*1024 + 3)*1024*1024*1024 + 3);

        assert_se(parse_size("12P", 1024, &bytes) == 0);
        assert_se(bytes == 12ULL * 1024*1024*1024*1024*1024);

        assert_se(parse_size("12P12P", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("3E 2P", 1024, &bytes) == 0);
        assert_se(bytes == (3 * 1024 + 2ULL) * 1024*1024*1024*1024*1024);

        assert_se(parse_size("12X", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("12.5X", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("12.5e3", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("1024E", 1024, &bytes) == -ERANGE);
        assert_se(parse_size("-1", 1024, &bytes) == -ERANGE);
        assert_se(parse_size("-1024E", 1024, &bytes) == -ERANGE);

        assert_se(parse_size("-1024P", 1024, &bytes) == -ERANGE);

        assert_se(parse_size("-10B 20K", 1024, &bytes) == -ERANGE);
}

static void test_parse_range(void) {
        unsigned lower, upper;

        /* Successful cases */
        assert_se(parse_range("111", &lower, &upper) == 0);
        assert_se(lower == 111);
        assert_se(upper == 111);

        assert_se(parse_range("111-123", &lower, &upper) == 0);
        assert_se(lower == 111);
        assert_se(upper == 123);

        assert_se(parse_range("123-111", &lower, &upper) == 0);
        assert_se(lower == 123);
        assert_se(upper == 111);

        assert_se(parse_range("123-123", &lower, &upper) == 0);
        assert_se(lower == 123);
        assert_se(upper == 123);

        assert_se(parse_range("0", &lower, &upper) == 0);
        assert_se(lower == 0);
        assert_se(upper == 0);

        assert_se(parse_range("0-15", &lower, &upper) == 0);
        assert_se(lower == 0);
        assert_se(upper == 15);

        assert_se(parse_range("15-0", &lower, &upper) == 0);
        assert_se(lower == 15);
        assert_se(upper == 0);

        assert_se(parse_range("128-65535", &lower, &upper) == 0);
        assert_se(lower == 128);
        assert_se(upper == 65535);

        assert_se(parse_range("1024-4294967295", &lower, &upper) == 0);
        assert_se(lower == 1024);
        assert_se(upper == 4294967295);

        /* Leading whitespace is acceptable */
        assert_se(parse_range(" 111", &lower, &upper) == 0);
        assert_se(lower == 111);
        assert_se(upper == 111);

        assert_se(parse_range(" 111-123", &lower, &upper) == 0);
        assert_se(lower == 111);
        assert_se(upper == 123);

        assert_se(parse_range("111- 123", &lower, &upper) == 0);
        assert_se(lower == 111);
        assert_se(upper == 123);

        assert_se(parse_range("\t111-\t123", &lower, &upper) == 0);
        assert_se(lower == 111);
        assert_se(upper == 123);

        assert_se(parse_range(" \t 111- \t 123", &lower, &upper) == 0);
        assert_se(lower == 111);
        assert_se(upper == 123);

        /* Error cases, make sure they fail as expected */
        lower = upper = 9999;
        assert_se(parse_range("111garbage", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("garbage111", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("garbage", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111-123garbage", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111garbage-123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        /* Empty string */
        lower = upper = 9999;
        assert_se(parse_range("", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        /* 111--123 will pass -123 to safe_atou which returns -ERANGE for negative */
        assert_se(parse_range("111--123", &lower, &upper) == -ERANGE);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("-111-123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111-123-", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111.4-123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111-123.4", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111,4-123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111-123,4", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        /* Error on trailing dash */
        assert_se(parse_range("111-", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111-123-", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111--", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111- ", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        /* Whitespace is not a separator */
        assert_se(parse_range("111 123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111\t123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111 \t 123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        /* Trailing whitespace is invalid (from safe_atou) */
        assert_se(parse_range("111 ", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111-123 ", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111 -123", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111 -123 ", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111\t-123\t", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        assert_se(parse_range("111 \t -123 \t ", &lower, &upper) == -EINVAL);
        assert_se(lower == 9999);
        assert_se(upper == 9999);

        /* Out of the "unsigned" range, this is 1<<64 */
        assert_se(parse_range("0-18446744073709551616", &lower, &upper) == -ERANGE);
        assert_se(lower == 9999);
        assert_se(upper == 9999);
}

static void test_safe_atolli(void) {
        int r;
        long long l;

        r = safe_atolli("12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atolli("  12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atolli("-12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atolli("  -12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atolli("12345678901234567890", &l);
        assert_se(r == -ERANGE);

        r = safe_atolli("-12345678901234567890", &l);
        assert_se(r == -ERANGE);

        r = safe_atolli("junk", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atou16(void) {
        int r;
        uint16_t l;

        r = safe_atou16("12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atou16("  12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atou16("123456", &l);
        assert_se(r == -ERANGE);

        r = safe_atou16("-1", &l);
        assert_se(r == -ERANGE);

        r = safe_atou16("  -1", &l);
        assert_se(r == -ERANGE);

        r = safe_atou16("junk", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atoi16(void) {
        int r;
        int16_t l;

        r = safe_atoi16("-12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atoi16("  -12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atoi16("32767", &l);
        assert_se(r == 0);
        assert_se(l == 32767);

        r = safe_atoi16("  32767", &l);
        assert_se(r == 0);
        assert_se(l == 32767);

        r = safe_atoi16("36536", &l);
        assert_se(r == -ERANGE);

        r = safe_atoi16("-32769", &l);
        assert_se(r == -ERANGE);

        r = safe_atoi16("junk", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atod(void) {
        int r;
        double d;
        char *e;

        r = safe_atod("junk", &d);
        assert_se(r == -EINVAL);

        r = safe_atod("0.2244", &d);
        assert_se(r == 0);
        assert_se(fabs(d - 0.2244) < 0.000001);

        r = safe_atod("0,5", &d);
        assert_se(r == -EINVAL);

        errno = 0;
        strtod("0,5", &e);
        assert_se(*e == ',');

        /* Check if this really is locale independent */
        if (setlocale(LC_NUMERIC, "de_DE.utf8")) {

                r = safe_atod("0.2244", &d);
                assert_se(r == 0);
                assert_se(fabs(d - 0.2244) < 0.000001);

                r = safe_atod("0,5", &d);
                assert_se(r == -EINVAL);

                errno = 0;
                assert_se(fabs(strtod("0,5", &e) - 0.5) < 0.00001);
        }

        /* And check again, reset */
        assert_se(setlocale(LC_NUMERIC, "C"));

        r = safe_atod("0.2244", &d);
        assert_se(r == 0);
        assert_se(fabs(d - 0.2244) < 0.000001);

        r = safe_atod("0,5", &d);
        assert_se(r == -EINVAL);

        errno = 0;
        strtod("0,5", &e);
        assert_se(*e == ',');
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_parse_boolean();
        test_parse_pid();
        test_parse_mode();
        test_parse_size();
        test_parse_range();
        test_safe_atolli();
        test_safe_atou16();
        test_safe_atoi16();
        test_safe_atod();

        return 0;
}
