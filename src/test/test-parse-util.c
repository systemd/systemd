/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "errno-list.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"

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

        r = parse_pid("", &pid);
        assert_se(r == -EINVAL);
}

static void test_parse_mode(void) {
        mode_t m;

        assert_se(parse_mode("-1", &m) < 0);
        assert_se(parse_mode("+1", &m) < 0);
        assert_se(parse_mode("", &m) < 0);
        assert_se(parse_mode("888", &m) < 0);
        assert_se(parse_mode("77777", &m) < 0);

        assert_se(parse_mode("544", &m) >= 0 && m == 0544);
        assert_se(parse_mode("0544", &m) >= 0 && m == 0544);
        assert_se(parse_mode("00544", &m) >= 0 && m == 0544);
        assert_se(parse_mode("777", &m) >= 0 && m == 0777);
        assert_se(parse_mode("0777", &m) >= 0 && m == 0777);
        assert_se(parse_mode("00777", &m) >= 0 && m == 0777);
        assert_se(parse_mode("7777", &m) >= 0 && m == 07777);
        assert_se(parse_mode("07777", &m) >= 0 && m == 07777);
        assert_se(parse_mode("007777", &m) >= 0 && m == 07777);
        assert_se(parse_mode("0", &m) >= 0 && m == 0);
        assert_se(parse_mode(" 1", &m) >= 0 && m == 1);
}

static void test_parse_size(void) {
        uint64_t bytes;

        assert_se(parse_size("", 1024, &bytes) == -EINVAL);

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

        assert_se(parse_range("-123", &lower, &upper) == -EINVAL);
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

        r = safe_atolli("0x5", &l);
        assert_se(r == 0);
        assert_se(l == 5);

        r = safe_atolli("0o6", &l);
        assert_se(r == 0);
        assert_se(l == 6);

        r = safe_atolli("0B101", &l);
        assert_se(r == 0);
        assert_se(l == 5);

        r = safe_atolli("12345678901234567890", &l);
        assert_se(r == -ERANGE);

        r = safe_atolli("-12345678901234567890", &l);
        assert_se(r == -ERANGE);

        r = safe_atolli("junk", &l);
        assert_se(r == -EINVAL);

        r = safe_atolli("123x", &l);
        assert_se(r == -EINVAL);

        r = safe_atolli("12.3", &l);
        assert_se(r == -EINVAL);

        r = safe_atolli("", &l);
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

        r = safe_atou16("123x", &l);
        assert_se(r == -EINVAL);

        r = safe_atou16("12.3", &l);
        assert_se(r == -EINVAL);

        r = safe_atou16("", &l);
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

        r = safe_atoi16("0o11", &l);
        assert_se(r == 0);
        assert_se(l == 9);

        r = safe_atoi16("0B110", &l);
        assert_se(r == 0);
        assert_se(l == 6);

        r = safe_atoi16("36536", &l);
        assert_se(r == -ERANGE);

        r = safe_atoi16("-32769", &l);
        assert_se(r == -ERANGE);

        r = safe_atoi16("junk", &l);
        assert_se(r == -EINVAL);

        r = safe_atoi16("123x", &l);
        assert_se(r == -EINVAL);

        r = safe_atoi16("12.3", &l);
        assert_se(r == -EINVAL);

        r = safe_atoi16("", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atoux16(void) {
        int r;
        uint16_t l;

        r = safe_atoux16("1234", &l);
        assert_se(r == 0);
        assert_se(l == 0x1234);

        r = safe_atoux16("abcd", &l);
        assert_se(r == 0);
        assert_se(l == 0xabcd);

        r = safe_atoux16("  1234", &l);
        assert_se(r == 0);
        assert_se(l == 0x1234);

        r = safe_atoux16("12345", &l);
        assert_se(r == -ERANGE);

        r = safe_atoux16("-1", &l);
        assert_se(r == -ERANGE);

        r = safe_atoux16("  -1", &l);
        assert_se(r == -ERANGE);

        r = safe_atoux16("0b1", &l);
        assert_se(r == 0);
        assert_se(l == 177);

        r = safe_atoux16("0o70", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux16("junk", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux16("123x", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux16("12.3", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux16("", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atou64(void) {
        int r;
        uint64_t l;

        r = safe_atou64("12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atou64("  12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atou64("0o11", &l);
        assert_se(r == 0);
        assert_se(l == 9);

        r = safe_atou64("0b11", &l);
        assert_se(r == 0);
        assert_se(l == 3);

        r = safe_atou64("18446744073709551617", &l);
        assert_se(r == -ERANGE);

        r = safe_atou64("-1", &l);
        assert_se(r == -ERANGE);

        r = safe_atou64("  -1", &l);
        assert_se(r == -ERANGE);

        r = safe_atou64("junk", &l);
        assert_se(r == -EINVAL);

        r = safe_atou64("123x", &l);
        assert_se(r == -EINVAL);

        r = safe_atou64("12.3", &l);
        assert_se(r == -EINVAL);

        r = safe_atou64("", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atoi64(void) {
        int r;
        int64_t l;

        r = safe_atoi64("-12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atoi64("  -12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atoi64("32767", &l);
        assert_se(r == 0);
        assert_se(l == 32767);

        r = safe_atoi64("  32767", &l);
        assert_se(r == 0);
        assert_se(l == 32767);

        r = safe_atoi64("  0o20", &l);
        assert_se(r == 0);
        assert_se(l == 16);

        r = safe_atoi64("  0b01010", &l);
        assert_se(r == 0);
        assert_se(l == 10);

        r = safe_atoi64("9223372036854775813", &l);
        assert_se(r == -ERANGE);

        r = safe_atoi64("-9223372036854775813", &l);
        assert_se(r == -ERANGE);

        r = safe_atoi64("junk", &l);
        assert_se(r == -EINVAL);

        r = safe_atoi64("123x", &l);
        assert_se(r == -EINVAL);

        r = safe_atoi64("12.3", &l);
        assert_se(r == -EINVAL);

        r = safe_atoi64("", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atoux64(void) {
        int r;
        uint64_t l;

        r = safe_atoux64("12345", &l);
        assert_se(r == 0);
        assert_se(l == 0x12345);

        r = safe_atoux64("  12345", &l);
        assert_se(r == 0);
        assert_se(l == 0x12345);

        r = safe_atoux64("0x12345", &l);
        assert_se(r == 0);
        assert_se(l == 0x12345);

        r = safe_atoux64("0b11011", &l);
        assert_se(r == 0);
        assert_se(l == 11603985);

        r = safe_atoux64("0o11011", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux64("18446744073709551617", &l);
        assert_se(r == -ERANGE);

        r = safe_atoux64("-1", &l);
        assert_se(r == -ERANGE);

        r = safe_atoux64("  -1", &l);
        assert_se(r == -ERANGE);

        r = safe_atoux64("junk", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux64("123x", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux64("12.3", &l);
        assert_se(r == -EINVAL);

        r = safe_atoux64("", &l);
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

        r = safe_atod("", &d);
        assert_se(r == -EINVAL);

        /* Check if this really is locale independent */
        if (setlocale(LC_NUMERIC, "de_DE.utf8")) {

                r = safe_atod("0.2244", &d);
                assert_se(r == 0);
                assert_se(fabs(d - 0.2244) < 0.000001);

                r = safe_atod("0,5", &d);
                assert_se(r == -EINVAL);

                errno = 0;
                assert_se(fabs(strtod("0,5", &e) - 0.5) < 0.00001);

                r = safe_atod("", &d);
                assert_se(r == -EINVAL);
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

        r = safe_atod("", &d);
        assert_se(r == -EINVAL);
}

static void test_parse_percent(void) {
        assert_se(parse_percent("") == -EINVAL);
        assert_se(parse_percent("foo") == -EINVAL);
        assert_se(parse_percent("0") == -EINVAL);
        assert_se(parse_percent("50") == -EINVAL);
        assert_se(parse_percent("100") == -EINVAL);
        assert_se(parse_percent("-1") == -EINVAL);
        assert_se(parse_percent("0%") == 0);
        assert_se(parse_percent("55%") == 55);
        assert_se(parse_percent("100%") == 100);
        assert_se(parse_percent("-7%") == -ERANGE);
        assert_se(parse_percent("107%") == -ERANGE);
        assert_se(parse_percent("%") == -EINVAL);
        assert_se(parse_percent("%%") == -EINVAL);
        assert_se(parse_percent("%1") == -EINVAL);
        assert_se(parse_percent("1%%") == -EINVAL);
        assert_se(parse_percent("3.2%") == -EINVAL);
}

static void test_parse_percent_unbounded(void) {
        assert_se(parse_percent_unbounded("101%") == 101);
        assert_se(parse_percent_unbounded("400%") == 400);
}

static void test_parse_permille(void) {
        assert_se(parse_permille("") == -EINVAL);
        assert_se(parse_permille("foo") == -EINVAL);
        assert_se(parse_permille("0") == -EINVAL);
        assert_se(parse_permille("50") == -EINVAL);
        assert_se(parse_permille("100") == -EINVAL);
        assert_se(parse_permille("-1") == -EINVAL);

        assert_se(parse_permille("0‰") == 0);
        assert_se(parse_permille("555‰") == 555);
        assert_se(parse_permille("1000‰") == 1000);
        assert_se(parse_permille("-7‰") == -ERANGE);
        assert_se(parse_permille("1007‰") == -ERANGE);
        assert_se(parse_permille("‰") == -EINVAL);
        assert_se(parse_permille("‰‰") == -EINVAL);
        assert_se(parse_permille("‰1") == -EINVAL);
        assert_se(parse_permille("1‰‰") == -EINVAL);
        assert_se(parse_permille("3.2‰") == -EINVAL);

        assert_se(parse_permille("0%") == 0);
        assert_se(parse_permille("55%") == 550);
        assert_se(parse_permille("55.5%") == 555);
        assert_se(parse_permille("100%") == 1000);
        assert_se(parse_permille("-7%") == -ERANGE);
        assert_se(parse_permille("107%") == -ERANGE);
        assert_se(parse_permille("%") == -EINVAL);
        assert_se(parse_permille("%%") == -EINVAL);
        assert_se(parse_permille("%1") == -EINVAL);
        assert_se(parse_permille("1%%") == -EINVAL);
        assert_se(parse_permille("3.21%") == -EINVAL);
}

static void test_parse_permille_unbounded(void) {
        assert_se(parse_permille_unbounded("1001‰") == 1001);
        assert_se(parse_permille_unbounded("4000‰") == 4000);
        assert_se(parse_permille_unbounded("2147483647‰") == 2147483647);
        assert_se(parse_permille_unbounded("2147483648‰") == -ERANGE);
        assert_se(parse_permille_unbounded("4294967295‰") == -ERANGE);
        assert_se(parse_permille_unbounded("4294967296‰") == -ERANGE);

        assert_se(parse_permille_unbounded("101%") == 1010);
        assert_se(parse_permille_unbounded("400%") == 4000);
        assert_se(parse_permille_unbounded("214748364.7%") == 2147483647);
        assert_se(parse_permille_unbounded("214748364.8%") == -ERANGE);
        assert_se(parse_permille_unbounded("429496729.5%") == -ERANGE);
        assert_se(parse_permille_unbounded("429496729.6%") == -ERANGE);
}

static void test_parse_nice(void) {
        int n;

        assert_se(parse_nice("0", &n) >= 0 && n == 0);
        assert_se(parse_nice("+0", &n) >= 0 && n == 0);
        assert_se(parse_nice("-1", &n) >= 0 && n == -1);
        assert_se(parse_nice("-2", &n) >= 0 && n == -2);
        assert_se(parse_nice("1", &n) >= 0 && n == 1);
        assert_se(parse_nice("2", &n) >= 0 && n == 2);
        assert_se(parse_nice("+1", &n) >= 0 && n == 1);
        assert_se(parse_nice("+2", &n) >= 0 && n == 2);
        assert_se(parse_nice("-20", &n) >= 0 && n == -20);
        assert_se(parse_nice("19", &n) >= 0 && n == 19);
        assert_se(parse_nice("+19", &n) >= 0 && n == 19);

        assert_se(parse_nice("", &n) == -EINVAL);
        assert_se(parse_nice("-", &n) == -EINVAL);
        assert_se(parse_nice("+", &n) == -EINVAL);
        assert_se(parse_nice("xx", &n) == -EINVAL);
        assert_se(parse_nice("-50", &n) == -ERANGE);
        assert_se(parse_nice("50", &n) == -ERANGE);
        assert_se(parse_nice("+50", &n) == -ERANGE);
        assert_se(parse_nice("-21", &n) == -ERANGE);
        assert_se(parse_nice("20", &n) == -ERANGE);
        assert_se(parse_nice("+20", &n) == -ERANGE);
}

static void test_parse_dev(void) {
        dev_t dev;

        assert_se(parse_dev("", &dev) == -EINVAL);
        assert_se(parse_dev("junk", &dev) == -EINVAL);
        assert_se(parse_dev("0", &dev) == -EINVAL);
        assert_se(parse_dev("5", &dev) == -EINVAL);
        assert_se(parse_dev("5:", &dev) == -EINVAL);
        assert_se(parse_dev(":5", &dev) == -EINVAL);
#if SIZEOF_DEV_T < 8
        assert_se(parse_dev("4294967295:4294967295", &dev) == -EINVAL);
#endif
        assert_se(parse_dev("8:11", &dev) >= 0 && major(dev) == 8 && minor(dev) == 11);
}

static void test_parse_errno(void) {
        assert_se(parse_errno("EILSEQ") == EILSEQ);
        assert_se(parse_errno("EINVAL") == EINVAL);
        assert_se(parse_errno("0") == 0);
        assert_se(parse_errno("1") == 1);
        assert_se(parse_errno("4095") == 4095);

        assert_se(parse_errno("-1") == -ERANGE);
        assert_se(parse_errno("-3") == -ERANGE);
        assert_se(parse_errno("4096") == -ERANGE);

        assert_se(parse_errno("") == -EINVAL);
        assert_se(parse_errno("12.3") == -EINVAL);
        assert_se(parse_errno("123junk") == -EINVAL);
        assert_se(parse_errno("junk123") == -EINVAL);
        assert_se(parse_errno("255EILSEQ") == -EINVAL);
        assert_se(parse_errno("EINVAL12") == -EINVAL);
        assert_se(parse_errno("-EINVAL") == -EINVAL);
        assert_se(parse_errno("EINVALaaa") == -EINVAL);
}

static void test_parse_syscall_and_errno(void) {
        _cleanup_free_ char *n = NULL;
        int e;

        assert_se(parse_syscall_and_errno("uname:EILSEQ", &n, &e) >= 0);
        assert_se(streq(n, "uname"));
        assert_se(e == errno_from_name("EILSEQ") && e >= 0);
        n = mfree(n);

        assert_se(parse_syscall_and_errno("uname:EINVAL", &n, &e) >= 0);
        assert_se(streq(n, "uname"));
        assert_se(e == errno_from_name("EINVAL") && e >= 0);
        n = mfree(n);

        assert_se(parse_syscall_and_errno("@sync:4095", &n, &e) >= 0);
        assert_se(streq(n, "@sync"));
        assert_se(e == 4095);
        n = mfree(n);

        /* If errno is omitted, then e is set to -1 */
        assert_se(parse_syscall_and_errno("mount", &n, &e) >= 0);
        assert_se(streq(n, "mount"));
        assert_se(e == -1);
        n = mfree(n);

        /* parse_syscall_and_errno() does not check the syscall name is valid or not. */
        assert_se(parse_syscall_and_errno("hoge:255", &n, &e) >= 0);
        assert_se(streq(n, "hoge"));
        assert_se(e == 255);
        n = mfree(n);

        /* The function checks the syscall name is empty or not. */
        assert_se(parse_syscall_and_errno("", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno(":255", &n, &e) == -EINVAL);

        /* errno must be a valid errno name or number between 0 and ERRNO_MAX == 4095 */
        assert_se(parse_syscall_and_errno("hoge:4096", &n, &e) == -ERANGE);
        assert_se(parse_syscall_and_errno("hoge:-3", &n, &e) == -ERANGE);
        assert_se(parse_syscall_and_errno("hoge:12.3", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:123junk", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:junk123", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:255:EILSEQ", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:-EINVAL", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:EINVALaaa", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:", &n, &e) == -EINVAL);
}

static void test_parse_mtu(void) {
        uint32_t mtu = 0;

        assert_se(parse_mtu(AF_UNSPEC, "1500", &mtu) >= 0 && mtu == 1500);
        assert_se(parse_mtu(AF_UNSPEC, "1400", &mtu) >= 0 && mtu == 1400);
        assert_se(parse_mtu(AF_UNSPEC, "65535", &mtu) >= 0 && mtu == 65535);
        assert_se(parse_mtu(AF_UNSPEC, "65536", &mtu) >= 0 && mtu == 65536);
        assert_se(parse_mtu(AF_UNSPEC, "4294967295", &mtu) >= 0 && mtu == 4294967295);
        assert_se(parse_mtu(AF_UNSPEC, "500", &mtu) >= 0 && mtu == 500);
        assert_se(parse_mtu(AF_UNSPEC, "1280", &mtu) >= 0 && mtu == 1280);
        assert_se(parse_mtu(AF_INET6, "1280", &mtu) >= 0 && mtu == 1280);
        assert_se(parse_mtu(AF_INET6, "1279", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_UNSPEC, "4294967296", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET6, "4294967296", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET6, "68", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_UNSPEC, "68", &mtu) >= 0 && mtu == 68);
        assert_se(parse_mtu(AF_UNSPEC, "67", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_UNSPEC, "0", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_UNSPEC, "", &mtu) == -EINVAL);
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
        test_safe_atoux16();
        test_safe_atou64();
        test_safe_atoi64();
        test_safe_atoux64();
        test_safe_atod();
        test_parse_percent();
        test_parse_percent_unbounded();
        test_parse_permille();
        test_parse_permille_unbounded();
        test_parse_nice();
        test_parse_dev();
        test_parse_errno();
        test_parse_syscall_and_errno();
        test_parse_mtu();

        return 0;
}
