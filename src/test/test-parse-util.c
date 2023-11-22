/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "errno-list.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_boolean) {
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

TEST(parse_pid) {
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

TEST(parse_mode) {
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

TEST(parse_size_iec) {
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

TEST(parse_size_si) {
        uint64_t bytes;

        assert_se(parse_size("", 1000, &bytes) == -EINVAL);

        assert_se(parse_size("111", 1000, &bytes) == 0);
        assert_se(bytes == 111);

        assert_se(parse_size("111.4", 1000, &bytes) == 0);
        assert_se(bytes == 111);

        assert_se(parse_size(" 112 B", 1000, &bytes) == 0);
        assert_se(bytes == 112);

        assert_se(parse_size(" 112.6 B", 1000, &bytes) == 0);
        assert_se(bytes == 112);

        assert_se(parse_size("3.5 K", 1000, &bytes) == 0);
        assert_se(bytes == 3*1000 + 500);

        assert_se(parse_size("3. K", 1000, &bytes) == 0);
        assert_se(bytes == 3*1000);

        assert_se(parse_size("3.0 K", 1000, &bytes) == 0);
        assert_se(bytes == 3*1000);

        assert_se(parse_size("3. 0 K", 1000, &bytes) == -EINVAL);

        assert_se(parse_size(" 4 M 11.5K", 1000, &bytes) == 0);
        assert_se(bytes == 4*1000*1000 + 11 * 1000 + 500);

        assert_se(parse_size("3B3.5G", 1000, &bytes) == -EINVAL);

        assert_se(parse_size("3.5G3B", 1000, &bytes) == 0);
        assert_se(bytes == 3ULL*1000*1000*1000 + 500*1000*1000 + 3);

        assert_se(parse_size("3.5G 4B", 1000, &bytes) == 0);
        assert_se(bytes == 3ULL*1000*1000*1000 + 500*1000*1000 + 4);

        assert_se(parse_size("3B3G4T", 1000, &bytes) == -EINVAL);

        assert_se(parse_size("4T3G3B", 1000, &bytes) == 0);
        assert_se(bytes == (4ULL*1000 + 3)*1000*1000*1000 + 3);

        assert_se(parse_size(" 4 T 3 G 3 B", 1000, &bytes) == 0);
        assert_se(bytes == (4ULL*1000 + 3)*1000*1000*1000 + 3);

        assert_se(parse_size("12P", 1000, &bytes) == 0);
        assert_se(bytes == 12ULL * 1000*1000*1000*1000*1000);

        assert_se(parse_size("12P12P", 1000, &bytes) == -EINVAL);

        assert_se(parse_size("3E 2P", 1000, &bytes) == 0);
        assert_se(bytes == (3 * 1000 + 2ULL) * 1000*1000*1000*1000*1000);

        assert_se(parse_size("12X", 1000, &bytes) == -EINVAL);

        assert_se(parse_size("12.5X", 1000, &bytes) == -EINVAL);

        assert_se(parse_size("12.5e3", 1000, &bytes) == -EINVAL);

        assert_se(parse_size("1000E", 1000, &bytes) == -ERANGE);
        assert_se(parse_size("-1", 1000, &bytes) == -ERANGE);
        assert_se(parse_size("-1000E", 1000, &bytes) == -ERANGE);

        assert_se(parse_size("-1000P", 1000, &bytes) == -ERANGE);

        assert_se(parse_size("-10B 20K", 1000, &bytes) == -ERANGE);
}

TEST(parse_range) {
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

TEST(safe_atou_bounded) {
        int r;
        unsigned x;

        r = safe_atou_bounded("12345", 12, 20000, &x);
        assert_se(r == 0);
        assert_se(x == 12345);

        r = safe_atou_bounded("12", 12, 20000, &x);
        assert_se(r == 0);
        assert_se(x == 12);

        r = safe_atou_bounded("20000", 12, 20000, &x);
        assert_se(r == 0);
        assert_se(x == 20000);

        r = safe_atou_bounded("-1", 12, 20000, &x);
        assert_se(r == -ERANGE);

        r = safe_atou_bounded("11", 12, 20000, &x);
        assert_se(r == -ERANGE);

        r = safe_atou_bounded("20001", 12, 20000, &x);
        assert_se(r == -ERANGE);
}

TEST(safe_atolli) {
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

TEST(safe_atou16) {
        int r;
        uint16_t l;

        r = safe_atou16("12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atou16("  12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atou16("+12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atou16("  +12345", &l);
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

TEST(safe_atoi16) {
        int r;
        int16_t l;

        r = safe_atoi16("-12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atoi16("  -12345", &l);
        assert_se(r == 0);
        assert_se(l == -12345);

        r = safe_atoi16("+12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atoi16("  +12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

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

TEST(safe_atoux16) {
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

TEST(safe_atou64) {
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

TEST(safe_atoi64) {
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

TEST(safe_atoux64) {
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

        r = safe_atoux64("+12345", &l);
        assert_se(r == 0);
        assert_se(l == 0x12345);

        r = safe_atoux64("  +12345", &l);
        assert_se(r == 0);
        assert_se(l == 0x12345);

        r = safe_atoux64("+0x12345", &l);
        assert_se(r == 0);
        assert_se(l == 0x12345);

        r = safe_atoux64("+0b11011", &l);
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

TEST(safe_atod) {
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

TEST(parse_nice) {
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

TEST(parse_errno) {
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

TEST(parse_fd) {
        assert_se(parse_fd("0") == 0);
        assert_se(parse_fd("1") == 1);

        assert_se(parse_fd("-1") == -EBADF);
        assert_se(parse_fd("-3") == -EBADF);

        assert_se(parse_fd("") == -EINVAL);
        assert_se(parse_fd("12.3") == -EINVAL);
        assert_se(parse_fd("123junk") == -EINVAL);
        assert_se(parse_fd("junk123") == -EINVAL);
}

TEST(parse_mtu) {
        uint32_t mtu = 0;

        assert_se(parse_mtu(AF_UNSPEC, "1500", &mtu) >= 0 && mtu == 1500);
        assert_se(parse_mtu(AF_UNSPEC, "1400", &mtu) >= 0 && mtu == 1400);
        assert_se(parse_mtu(AF_UNSPEC, "65535", &mtu) >= 0 && mtu == 65535);
        assert_se(parse_mtu(AF_UNSPEC, "65536", &mtu) >= 0 && mtu == 65536);
        assert_se(parse_mtu(AF_UNSPEC, "4294967295", &mtu) >= 0 && mtu == 4294967295);
        assert_se(parse_mtu(AF_UNSPEC, "500", &mtu) >= 0 && mtu == 500);
        assert_se(parse_mtu(AF_UNSPEC, "1280", &mtu) >= 0 && mtu == 1280);
        assert_se(parse_mtu(AF_UNSPEC, "4294967296", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_UNSPEC, "68", &mtu) >= 0 && mtu == 68);
        assert_se(parse_mtu(AF_UNSPEC, "67", &mtu) >= 0 && mtu == 67);
        assert_se(parse_mtu(AF_UNSPEC, "0", &mtu) >= 0 && mtu == 0);
        assert_se(parse_mtu(AF_UNSPEC, "", &mtu) == -EINVAL);

        assert_se(parse_mtu(AF_INET, "1500", &mtu) >= 0 && mtu == 1500);
        assert_se(parse_mtu(AF_INET, "1400", &mtu) >= 0 && mtu == 1400);
        assert_se(parse_mtu(AF_INET, "65535", &mtu) >= 0 && mtu == 65535);
        assert_se(parse_mtu(AF_INET, "65536", &mtu) >= 0 && mtu == 65536);
        assert_se(parse_mtu(AF_INET, "4294967295", &mtu) >= 0 && mtu == 4294967295);
        assert_se(parse_mtu(AF_INET, "500", &mtu) >= 0 && mtu == 500);
        assert_se(parse_mtu(AF_INET, "1280", &mtu) >= 0 && mtu == 1280);
        assert_se(parse_mtu(AF_INET, "4294967296", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET, "68", &mtu) >= 0 && mtu == 68);
        assert_se(parse_mtu(AF_INET, "67", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET, "0", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET, "", &mtu) == -EINVAL);

        assert_se(parse_mtu(AF_INET6, "1280", &mtu) >= 0 && mtu == 1280);
        assert_se(parse_mtu(AF_INET6, "1279", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET6, "4294967296", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET6, "68", &mtu) == -ERANGE);
        assert_se(parse_mtu(AF_INET6, "", &mtu) == -EINVAL);
}

TEST(parse_loadavg_fixed_point) {
        loadavg_t fp;

        assert_se(parse_loadavg_fixed_point("1.23", &fp) == 0);
        assert_se(LOADAVG_INT_SIDE(fp) == 1);
        assert_se(LOADAVG_DECIMAL_SIDE(fp) == 23);

        assert_se(parse_loadavg_fixed_point("1.80", &fp) == 0);
        assert_se(LOADAVG_INT_SIDE(fp) == 1);
        assert_se(LOADAVG_DECIMAL_SIDE(fp) == 80);

        assert_se(parse_loadavg_fixed_point("0.07", &fp) == 0);
        assert_se(LOADAVG_INT_SIDE(fp) == 0);
        assert_se(LOADAVG_DECIMAL_SIDE(fp) == 7);

        assert_se(parse_loadavg_fixed_point("0.00", &fp) == 0);
        assert_se(LOADAVG_INT_SIDE(fp) == 0);
        assert_se(LOADAVG_DECIMAL_SIDE(fp) == 0);

        assert_se(parse_loadavg_fixed_point("4096.57", &fp) == 0);
        assert_se(LOADAVG_INT_SIDE(fp) == 4096);
        assert_se(LOADAVG_DECIMAL_SIDE(fp) == 57);

        /* Caps out at 2 digit fracs */
        assert_se(parse_loadavg_fixed_point("1.100", &fp) == -ERANGE);

        assert_se(parse_loadavg_fixed_point("4096.4096", &fp) == -ERANGE);
        assert_se(parse_loadavg_fixed_point("-4000.5", &fp) == -ERANGE);
        assert_se(parse_loadavg_fixed_point("18446744073709551615.5", &fp) == -ERANGE);
        assert_se(parse_loadavg_fixed_point("foobar", &fp) == -EINVAL);
        assert_se(parse_loadavg_fixed_point("3333", &fp) == -EINVAL);
        assert_se(parse_loadavg_fixed_point("1.2.3", &fp) == -EINVAL);
        assert_se(parse_loadavg_fixed_point(".", &fp) == -EINVAL);
        assert_se(parse_loadavg_fixed_point("", &fp) == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
