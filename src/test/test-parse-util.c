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
        ASSERT_OK_EQ(parse_boolean("1"), 1);
        ASSERT_OK_EQ(parse_boolean("y"), 1);
        ASSERT_OK_EQ(parse_boolean("Y"), 1);
        ASSERT_OK_EQ(parse_boolean("yes"), 1);
        ASSERT_OK_EQ(parse_boolean("YES"), 1);
        ASSERT_OK_EQ(parse_boolean("true"), 1);
        ASSERT_OK_EQ(parse_boolean("TRUE"), 1);
        ASSERT_OK_EQ(parse_boolean("on"), 1);
        ASSERT_OK_EQ(parse_boolean("ON"), 1);

        ASSERT_OK_ZERO(parse_boolean("0"));
        ASSERT_OK_ZERO(parse_boolean("n"));
        ASSERT_OK_ZERO(parse_boolean("N"));
        ASSERT_OK_ZERO(parse_boolean("no"));
        ASSERT_OK_ZERO(parse_boolean("NO"));
        ASSERT_OK_ZERO(parse_boolean("false"));
        ASSERT_OK_ZERO(parse_boolean("FALSE"));
        ASSERT_OK_ZERO(parse_boolean("off"));
        ASSERT_OK_ZERO(parse_boolean("OFF"));

        ASSERT_FAIL(parse_boolean("garbage"));
        ASSERT_FAIL(parse_boolean(""));
        ASSERT_FAIL(parse_boolean("full"));
}

TEST(parse_pid) {
        pid_t pid;

        ASSERT_OK_ZERO(parse_pid("100", &pid));
        ASSERT_EQ(pid, 100);

        ASSERT_OK_ZERO(parse_pid("0x7FFFFFFF", &pid));
        ASSERT_EQ(pid, 2147483647);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        ASSERT_ERROR(parse_pid("0", &pid), ERANGE);
        ASSERT_EQ(pid, 65);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        ASSERT_ERROR(parse_pid("-100", &pid), ERANGE);
        ASSERT_EQ(pid, 65);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        ASSERT_ERROR(parse_pid("0xFFFFFFFFFFFFFFFFF", &pid), ERANGE);
        ASSERT_EQ(pid, 65);

        ASSERT_ERROR(parse_pid("junk", &pid), EINVAL);

        ASSERT_ERROR(parse_pid("", &pid), EINVAL);
}

TEST(parse_mode) {
        mode_t m;

        ASSERT_FAIL(parse_mode("-1", &m));
        ASSERT_FAIL(parse_mode("+1", &m));
        ASSERT_FAIL(parse_mode("", &m));
        ASSERT_FAIL(parse_mode("888", &m));
        ASSERT_FAIL(parse_mode("77777", &m));

        ASSERT_OK(parse_mode("544", &m));
        ASSERT_EQ(m, 0544U);

        ASSERT_OK(parse_mode("0544", &m));
        ASSERT_EQ(m, 0544U);

        ASSERT_OK(parse_mode("00544", &m));
        ASSERT_EQ(m, 0544U);

        ASSERT_OK(parse_mode("777", &m));
        ASSERT_EQ(m, 0777U);

        ASSERT_OK(parse_mode("0777", &m));
        ASSERT_EQ(m, 0777U);

        ASSERT_OK(parse_mode("00777", &m));
        ASSERT_EQ(m, 0777U);

        ASSERT_OK(parse_mode("7777", &m));
        ASSERT_EQ(m, 07777U);

        ASSERT_OK(parse_mode("07777", &m));
        ASSERT_EQ(m, 07777U);

        ASSERT_OK(parse_mode("007777", &m));
        ASSERT_EQ(m, 07777U);

        ASSERT_OK(parse_mode("0", &m));
        ASSERT_EQ(m, 0U);

        ASSERT_OK(parse_mode(" 1", &m));
        ASSERT_EQ(m, 1U);
}

TEST(parse_size_iec) {
        uint64_t bytes;

        ASSERT_ERROR(parse_size("", 1024, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("111", 1024, &bytes));
        ASSERT_EQ(bytes, 111ULL);

        ASSERT_OK_ZERO(parse_size("111.4", 1024, &bytes));
        ASSERT_EQ(bytes, 111ULL);

        ASSERT_OK_ZERO(parse_size(" 112 B", 1024, &bytes));
        ASSERT_EQ(bytes, 112ULL);

        ASSERT_OK_ZERO(parse_size(" 112.6 B", 1024, &bytes));
        ASSERT_EQ(bytes, 112ULL);

        ASSERT_OK_ZERO(parse_size("3.5 K", 1024, &bytes));
        ASSERT_EQ(bytes, 3ULL*1024 + 512);

        ASSERT_OK_ZERO(parse_size("3. K", 1024, &bytes));
        ASSERT_EQ(bytes, 3ULL*1024);

        ASSERT_OK_ZERO(parse_size("3.0 K", 1024, &bytes));
        ASSERT_EQ(bytes, 3ULL*1024);

        ASSERT_ERROR(parse_size("3. 0 K", 1024, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size(" 4 M 11.5K", 1024, &bytes));
        ASSERT_EQ(bytes, 4ULL*1024*1024 + 11*1024 + 512);

        ASSERT_ERROR(parse_size("3B3.5G", 1024, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("3.5G3B", 1024, &bytes));
        ASSERT_EQ(bytes, 3ULL*1024*1024*1024 + 512*1024*1024 + 3);

        ASSERT_OK_ZERO(parse_size("3.5G 4B", 1024, &bytes));
        ASSERT_EQ(bytes, 3ULL*1024*1024*1024 + 512*1024*1024 + 4);

        ASSERT_ERROR(parse_size("3B3G4T", 1024, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("4T3G3B", 1024, &bytes));
        ASSERT_EQ(bytes, (4ULL*1024 + 3)*1024*1024*1024 + 3);

        ASSERT_OK_ZERO(parse_size(" 4 T 3 G 3 B", 1024, &bytes));
        ASSERT_EQ(bytes, (4ULL*1024 + 3)*1024*1024*1024 + 3);

        ASSERT_OK_ZERO(parse_size("12P", 1024, &bytes));
        ASSERT_EQ(bytes, 12ULL * 1024*1024*1024*1024*1024);

        ASSERT_ERROR(parse_size("12P12P", 1024, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("3E 2P", 1024, &bytes));
        ASSERT_EQ(bytes, (3 * 1024 + 2ULL) * 1024*1024*1024*1024*1024);

        ASSERT_ERROR(parse_size("12X", 1024, &bytes), EINVAL);

        ASSERT_ERROR(parse_size("12.5X", 1024, &bytes), EINVAL);

        ASSERT_ERROR(parse_size("12.5e3", 1024, &bytes), EINVAL);

        ASSERT_ERROR(parse_size("1024E", 1024, &bytes), ERANGE);
        ASSERT_ERROR(parse_size("-1", 1024, &bytes), ERANGE);
        ASSERT_ERROR(parse_size("-1024E", 1024, &bytes), ERANGE);

        ASSERT_ERROR(parse_size("-1024P", 1024, &bytes), ERANGE);

        ASSERT_ERROR(parse_size("-10B 20K", 1024, &bytes), ERANGE);
}

TEST(parse_size_si) {
        uint64_t bytes;

        ASSERT_ERROR(parse_size("", 1000, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("111", 1000, &bytes));
        ASSERT_EQ(bytes, 111ULL);

        ASSERT_OK_ZERO(parse_size("111.4", 1000, &bytes));
        ASSERT_EQ(bytes, 111ULL);

        ASSERT_OK_ZERO(parse_size(" 112 B", 1000, &bytes));
        ASSERT_EQ(bytes, 112ULL);

        ASSERT_OK_ZERO(parse_size(" 112.6 B", 1000, &bytes));
        ASSERT_EQ(bytes, 112ULL);

        ASSERT_OK_ZERO(parse_size("3.5 K", 1000, &bytes));
        ASSERT_EQ(bytes, 3ULL*1000 + 500);

        ASSERT_OK_ZERO(parse_size("3. K", 1000, &bytes));
        ASSERT_EQ(bytes, 3ULL*1000);

        ASSERT_OK_ZERO(parse_size("3.0 K", 1000, &bytes));
        ASSERT_EQ(bytes, 3ULL*1000);

        ASSERT_ERROR(parse_size("3. 0 K", 1000, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size(" 4 M 11.5K", 1000, &bytes));
        ASSERT_EQ(bytes, 4ULL*1000*1000 + 11 * 1000 + 500);

        ASSERT_ERROR(parse_size("3B3.5G", 1000, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("3.5G3B", 1000, &bytes));
        ASSERT_EQ(bytes, 3ULL*1000*1000*1000 + 500*1000*1000 + 3);

        ASSERT_OK_ZERO(parse_size("3.5G 4B", 1000, &bytes));
        ASSERT_EQ(bytes, 3ULL*1000*1000*1000 + 500*1000*1000 + 4);

        ASSERT_ERROR(parse_size("3B3G4T", 1000, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("4T3G3B", 1000, &bytes));
        ASSERT_EQ(bytes, (4ULL*1000 + 3)*1000*1000*1000 + 3);

        ASSERT_OK_ZERO(parse_size(" 4 T 3 G 3 B", 1000, &bytes));
        ASSERT_EQ(bytes, (4ULL*1000 + 3)*1000*1000*1000 + 3);

        ASSERT_OK_ZERO(parse_size("12P", 1000, &bytes));
        ASSERT_EQ(bytes, 12ULL * 1000*1000*1000*1000*1000);

        ASSERT_ERROR(parse_size("12P12P", 1000, &bytes), EINVAL);

        ASSERT_OK_ZERO(parse_size("3E 2P", 1000, &bytes));
        ASSERT_EQ(bytes, (3 * 1000 + 2ULL) * 1000*1000*1000*1000*1000);

        ASSERT_ERROR(parse_size("12X", 1000, &bytes), EINVAL);

        ASSERT_ERROR(parse_size("12.5X", 1000, &bytes), EINVAL);

        ASSERT_ERROR(parse_size("12.5e3", 1000, &bytes), EINVAL);

        ASSERT_ERROR(parse_size("1000E", 1000, &bytes), ERANGE);
        ASSERT_ERROR(parse_size("-1", 1000, &bytes), ERANGE);
        ASSERT_ERROR(parse_size("-1000E", 1000, &bytes), ERANGE);

        ASSERT_ERROR(parse_size("-1000P", 1000, &bytes), ERANGE);

        ASSERT_ERROR(parse_size("-10B 20K", 1000, &bytes), ERANGE);
}

TEST(parse_range) {
        unsigned lower, upper;

        /* Successful cases */
        ASSERT_OK_ZERO(parse_range("111", &lower, &upper));
        ASSERT_EQ(lower, 111ULL);
        ASSERT_EQ(upper, 111ULL);

        ASSERT_OK_ZERO(parse_range("111-123", &lower, &upper));
        ASSERT_EQ(lower, 111ULL);
        ASSERT_EQ(upper, 123ULL);

        ASSERT_OK_ZERO(parse_range("123-111", &lower, &upper));
        ASSERT_EQ(lower, 123ULL);
        ASSERT_EQ(upper, 111ULL);

        ASSERT_OK_ZERO(parse_range("123-123", &lower, &upper));
        ASSERT_EQ(lower, 123ULL);
        ASSERT_EQ(upper, 123ULL);

        ASSERT_OK_ZERO(parse_range("0", &lower, &upper));
        ASSERT_EQ(lower, 0ULL);
        ASSERT_EQ(upper, 0ULL);

        ASSERT_OK_ZERO(parse_range("0-15", &lower, &upper));
        ASSERT_EQ(lower, 0ULL);
        ASSERT_EQ(upper, 15ULL);

        ASSERT_OK_ZERO(parse_range("15-0", &lower, &upper));
        ASSERT_EQ(lower, 15ULL);
        ASSERT_EQ(upper, 0ULL);

        ASSERT_OK_ZERO(parse_range("128-65535", &lower, &upper));
        ASSERT_EQ(lower, 128ULL);
        ASSERT_EQ(upper, 65535ULL);

        ASSERT_OK_ZERO(parse_range("1024-4294967295", &lower, &upper));
        ASSERT_EQ(lower, 1024ULL);
        ASSERT_EQ(upper, 4294967295ULL);

        /* Leading whitespace is acceptable */
        ASSERT_OK_ZERO(parse_range(" 111", &lower, &upper));
        ASSERT_EQ(lower, 111ULL);
        ASSERT_EQ(upper, 111ULL);

        ASSERT_OK_ZERO(parse_range(" 111-123", &lower, &upper));
        ASSERT_EQ(lower, 111ULL);
        ASSERT_EQ(upper, 123ULL);

        ASSERT_OK_ZERO(parse_range("111- 123", &lower, &upper));
        ASSERT_EQ(lower, 111ULL);
        ASSERT_EQ(upper, 123ULL);

        ASSERT_OK_ZERO(parse_range("\t111-\t123", &lower, &upper));
        ASSERT_EQ(lower, 111ULL);
        ASSERT_EQ(upper, 123ULL);

        ASSERT_OK_ZERO(parse_range(" \t 111- \t 123", &lower, &upper));
        ASSERT_EQ(lower, 111ULL);
        ASSERT_EQ(upper, 123ULL);

        /* Error cases, make sure they fail as expected */
        lower = upper = 9999;
        ASSERT_ERROR(parse_range("111garbage", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("garbage111", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("garbage", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111-123garbage", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111garbage-123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        /* Empty string */
        lower = upper = 9999;
        ASSERT_ERROR(parse_range("", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        /* 111--123 will pass -123 to safe_atou which returns -ERANGE for negative */
        ASSERT_ERROR(parse_range("111--123", &lower, &upper), ERANGE);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("-123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("-111-123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111-123-", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111.4-123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111-123.4", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111,4-123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111-123,4", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        /* Error on trailing dash */
        ASSERT_ERROR(parse_range("111-", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111-123-", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111--", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111- ", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        /* Whitespace is not a separator */
        ASSERT_ERROR(parse_range("111 123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111\t123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111 \t 123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        /* Trailing whitespace is invalid (from safe_atou) */
        ASSERT_ERROR(parse_range("111 ", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111-123 ", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111 -123", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111 -123 ", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111\t-123\t", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        ASSERT_ERROR(parse_range("111 \t -123 \t ", &lower, &upper), EINVAL);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);

        /* Out of the "unsigned" range, this is 1<<64 */
        ASSERT_ERROR(parse_range("0-18446744073709551616", &lower, &upper), ERANGE);
        ASSERT_EQ(lower, 9999ULL);
        ASSERT_EQ(upper, 9999ULL);
}

TEST(safe_atou_bounded) {
        unsigned x;

        ASSERT_OK_ZERO(safe_atou_bounded("12345", 12, 20000, &x));
        ASSERT_EQ(x, 12345ULL);

        ASSERT_OK_ZERO(safe_atou_bounded("12", 12, 20000, &x));
        ASSERT_EQ(x, 12ULL);

        ASSERT_OK_ZERO(safe_atou_bounded("20000", 12, 20000, &x));
        ASSERT_EQ(x, 20000ULL);

        ASSERT_ERROR(safe_atou_bounded("-1", 12, 20000, &x), ERANGE);
        ASSERT_ERROR(safe_atou_bounded("11", 12, 20000, &x), ERANGE);
        ASSERT_ERROR(safe_atou_bounded("20001", 12, 20000, &x), ERANGE);
}

TEST(safe_atolli) {
        long long l;

        ASSERT_OK_ZERO(safe_atolli("12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_OK_ZERO(safe_atolli("  12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_OK_ZERO(safe_atolli("-12345", &l));
        ASSERT_EQ(l, -12345);

        ASSERT_OK_ZERO(safe_atolli("  -12345", &l));
        ASSERT_EQ(l, -12345);

        ASSERT_OK_ZERO(safe_atolli("0x5", &l));
        ASSERT_EQ(l, 5);

        ASSERT_OK_ZERO(safe_atolli("0o6", &l));
        ASSERT_EQ(l, 6);

        ASSERT_OK_ZERO(safe_atolli("0B101", &l));
        ASSERT_EQ(l, 5);

        ASSERT_ERROR(safe_atolli("12345678901234567890", &l), ERANGE);
        ASSERT_ERROR(safe_atolli("-12345678901234567890", &l), ERANGE);
        ASSERT_ERROR(safe_atolli("junk", &l), EINVAL);
        ASSERT_ERROR(safe_atolli("123x", &l), EINVAL);
        ASSERT_ERROR(safe_atolli("12.3", &l), EINVAL);
        ASSERT_ERROR(safe_atolli("", &l), EINVAL);
}

TEST(safe_atou16) {
        uint16_t l;

        ASSERT_OK_ZERO(safe_atou16("12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_OK_ZERO(safe_atou16("  12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_OK_ZERO(safe_atou16("+12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_OK_ZERO(safe_atou16("  +12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_ERROR(safe_atou16("123456", &l), ERANGE);
        ASSERT_ERROR(safe_atou16("-1", &l), ERANGE);
        ASSERT_ERROR(safe_atou16("  -1", &l), ERANGE);
        ASSERT_ERROR(safe_atou16("junk", &l), EINVAL);
        ASSERT_ERROR(safe_atou16("123x", &l), EINVAL);
        ASSERT_ERROR(safe_atou16("12.3", &l), EINVAL);
        ASSERT_ERROR(safe_atou16("", &l), EINVAL);
}

TEST(safe_atoi16) {
        int16_t l;

        ASSERT_OK_ZERO(safe_atoi16("-12345", &l));
        ASSERT_EQ(l, -12345);

        ASSERT_OK_ZERO(safe_atoi16("  -12345", &l));
        ASSERT_EQ(l, -12345);

        ASSERT_OK_ZERO(safe_atoi16("+12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_OK_ZERO(safe_atoi16("  +12345", &l));
        ASSERT_EQ(l, 12345);

        ASSERT_OK_ZERO(safe_atoi16("32767", &l));
        ASSERT_EQ(l, 32767);

        ASSERT_OK_ZERO(safe_atoi16("  32767", &l));
        ASSERT_EQ(l, 32767);

        ASSERT_OK_ZERO(safe_atoi16("0o11", &l));
        ASSERT_EQ(l, 9);

        ASSERT_OK_ZERO(safe_atoi16("0B110", &l));
        ASSERT_EQ(l, 6);

        ASSERT_ERROR(safe_atoi16("36536", &l), ERANGE);
        ASSERT_ERROR(safe_atoi16("-32769", &l), ERANGE);
        ASSERT_ERROR(safe_atoi16("junk", &l), EINVAL);
        ASSERT_ERROR(safe_atoi16("123x", &l), EINVAL);
        ASSERT_ERROR(safe_atoi16("12.3", &l), EINVAL);
        ASSERT_ERROR(safe_atoi16("", &l), EINVAL);
}

TEST(safe_atoux16) {
        uint16_t l;

        ASSERT_OK_ZERO(safe_atoux16("1234", &l));
        ASSERT_EQ(l, 0x1234);

        ASSERT_OK_ZERO(safe_atoux16("abcd", &l));
        ASSERT_EQ(l, 0xabcd);

        ASSERT_OK_ZERO(safe_atoux16("  1234", &l));
        ASSERT_EQ(l, 0x1234);

        ASSERT_ERROR(safe_atoux16("12345", &l), ERANGE);

        ASSERT_ERROR(safe_atoux16("-1", &l), ERANGE);

        ASSERT_ERROR(safe_atoux16("  -1", &l), ERANGE);

        ASSERT_OK_ZERO(safe_atoux16("0b1", &l));
        ASSERT_EQ(l, 177);

        ASSERT_ERROR(safe_atoux16("0o70", &l), EINVAL);
        ASSERT_ERROR(safe_atoux16("junk", &l), EINVAL);
        ASSERT_ERROR(safe_atoux16("123x", &l), EINVAL);
        ASSERT_ERROR(safe_atoux16("12.3", &l), EINVAL);
        ASSERT_ERROR(safe_atoux16("", &l), EINVAL);
}

TEST(safe_atou64) {
        uint64_t l;

        ASSERT_OK_ZERO(safe_atou64("12345", &l));
        ASSERT_EQ(l, 12345U);

        ASSERT_OK_ZERO(safe_atou64("  12345", &l));
        ASSERT_EQ(l, 12345U);

        ASSERT_OK_ZERO(safe_atou64("0o11", &l));
        ASSERT_EQ(l, 9U);

        ASSERT_OK_ZERO(safe_atou64("0b11", &l));
        ASSERT_EQ(l, 3U);

        ASSERT_ERROR(safe_atou64("18446744073709551617", &l), ERANGE);
        ASSERT_ERROR(safe_atou64("-1", &l), ERANGE);
        ASSERT_ERROR(safe_atou64("  -1", &l), ERANGE);
        ASSERT_ERROR(safe_atou64("junk", &l), EINVAL);
        ASSERT_ERROR(safe_atou64("123x", &l), EINVAL);
        ASSERT_ERROR(safe_atou64("12.3", &l), EINVAL);
        ASSERT_ERROR(safe_atou64("", &l), EINVAL);
}

TEST(safe_atoi64) {
        int64_t l;

        ASSERT_OK_ZERO(safe_atoi64("-12345", &l));
        ASSERT_EQ(l, -12345);

        ASSERT_OK_ZERO(safe_atoi64("  -12345", &l));
        ASSERT_EQ(l, -12345);

        ASSERT_OK_ZERO(safe_atoi64("32767", &l));
        ASSERT_EQ(l, 32767);

        ASSERT_OK_ZERO(safe_atoi64("  32767", &l));
        ASSERT_EQ(l, 32767);

        ASSERT_OK_ZERO(safe_atoi64("  0o20", &l));
        ASSERT_EQ(l, 16);

        ASSERT_OK_ZERO(safe_atoi64("  0b01010", &l));
        ASSERT_EQ(l, 10);

        ASSERT_ERROR(safe_atoi64("9223372036854775813", &l), ERANGE);
        ASSERT_ERROR(safe_atoi64("-9223372036854775813", &l), ERANGE);
        ASSERT_ERROR(safe_atoi64("junk", &l), EINVAL);
        ASSERT_ERROR(safe_atoi64("123x", &l), EINVAL);
        ASSERT_ERROR(safe_atoi64("12.3", &l), EINVAL);
        ASSERT_ERROR(safe_atoi64("", &l), EINVAL);
}

TEST(safe_atoux64) {
        uint64_t l;

        ASSERT_OK_ZERO(safe_atoux64("12345", &l));
        ASSERT_EQ(l, 0x12345U);

        ASSERT_OK_ZERO(safe_atoux64("  12345", &l));
        ASSERT_EQ(l, 0x12345U);

        ASSERT_OK_ZERO(safe_atoux64("0x12345", &l));
        ASSERT_EQ(l, 0x12345U);

        ASSERT_OK_ZERO(safe_atoux64("0b11011", &l));
        ASSERT_EQ(l, 11603985U);

        ASSERT_OK_ZERO(safe_atoux64("+12345", &l));
        ASSERT_EQ(l, 0x12345U);

        ASSERT_OK_ZERO(safe_atoux64("  +12345", &l));
        ASSERT_EQ(l, 0x12345U);

        ASSERT_OK_ZERO(safe_atoux64("+0x12345", &l));
        ASSERT_EQ(l, 0x12345U);

        ASSERT_OK_ZERO(safe_atoux64("+0b11011", &l));
        ASSERT_EQ(l, 11603985U);

        ASSERT_ERROR(safe_atoux64("0o11011", &l), EINVAL);
        ASSERT_ERROR(safe_atoux64("18446744073709551617", &l), ERANGE);
        ASSERT_ERROR(safe_atoux64("-1", &l), ERANGE);
        ASSERT_ERROR(safe_atoux64("  -1", &l), ERANGE);
        ASSERT_ERROR(safe_atoux64("junk", &l), EINVAL);
        ASSERT_ERROR(safe_atoux64("123x", &l), EINVAL);
        ASSERT_ERROR(safe_atoux64("12.3", &l), EINVAL);
        ASSERT_ERROR(safe_atoux64("", &l), EINVAL);
}

TEST(safe_atod) {
        double d;
        char *e;

        ASSERT_ERROR(safe_atod("junk", &d), EINVAL);

        ASSERT_OK_ZERO(safe_atod("0.2244", &d));
        assert_se(fabs(d - 0.2244) < 0.000001);

        ASSERT_ERROR(safe_atod("0,5", &d), EINVAL);

        errno = 0;
        strtod("0,5", &e);
        assert_se(*e == ',');

        ASSERT_ERROR(safe_atod("", &d), EINVAL);

        /* Check if this really is locale independent */
        if (setlocale(LC_NUMERIC, "de_DE.utf8")) {

                ASSERT_OK_ZERO(safe_atod("0.2244", &d));
                assert_se(fabs(d - 0.2244) < 0.000001);

                ASSERT_ERROR(safe_atod("0,5", &d), EINVAL);

                errno = 0;
                assert_se(fabs(strtod("0,5", &e) - 0.5) < 0.00001);

                ASSERT_ERROR(safe_atod("", &d), EINVAL);
        }

        /* And check again, reset */
        ASSERT_NOT_NULL(setlocale(LC_NUMERIC, "C"));

        ASSERT_OK_ZERO(safe_atod("0.2244", &d));
        assert_se(fabs(d - 0.2244) < 0.000001);

        ASSERT_ERROR(safe_atod("0,5", &d), EINVAL);

        errno = 0;
        strtod("0,5", &e);
        assert_se(*e == ',');

        ASSERT_ERROR(safe_atod("", &d), EINVAL);
}

TEST(parse_nice) {
        int n;

        ASSERT_OK(parse_nice("0", &n));
        ASSERT_EQ(n, 0);

        ASSERT_OK(parse_nice("+0", &n));
        ASSERT_EQ(n, 0);

        ASSERT_OK(parse_nice("-1", &n));
        ASSERT_EQ(n, -1);

        ASSERT_OK(parse_nice("-2", &n));
        ASSERT_EQ(n, -2);

        ASSERT_OK(parse_nice("1", &n));
        ASSERT_EQ(n, 1);

        ASSERT_OK(parse_nice("2", &n));
        ASSERT_EQ(n, 2);

        ASSERT_OK(parse_nice("+1", &n));
        ASSERT_EQ(n, 1);

        ASSERT_OK(parse_nice("+2", &n));
        ASSERT_EQ(n, 2);

        ASSERT_OK(parse_nice("-20", &n));
        ASSERT_EQ(n, -20);

        ASSERT_OK(parse_nice("19", &n));
        ASSERT_EQ(n, 19);

        ASSERT_OK(parse_nice("+19", &n));
        ASSERT_EQ(n, 19);

        ASSERT_ERROR(parse_nice("", &n), EINVAL);
        ASSERT_ERROR(parse_nice("-", &n), EINVAL);
        ASSERT_ERROR(parse_nice("+", &n), EINVAL);
        ASSERT_ERROR(parse_nice("xx", &n), EINVAL);
        ASSERT_ERROR(parse_nice("-50", &n), ERANGE);
        ASSERT_ERROR(parse_nice("50", &n), ERANGE);
        ASSERT_ERROR(parse_nice("+50", &n), ERANGE);
        ASSERT_ERROR(parse_nice("-21", &n), ERANGE);
        ASSERT_ERROR(parse_nice("20", &n), ERANGE);
        ASSERT_ERROR(parse_nice("+20", &n), ERANGE);
}

TEST(parse_errno) {
        ASSERT_OK_EQ(parse_errno("EILSEQ"), EILSEQ);
        ASSERT_OK_EQ(parse_errno("EINVAL"), EINVAL);
        ASSERT_OK_EQ(parse_errno("0"), 0);
        ASSERT_OK_EQ(parse_errno("1"), 1);
        ASSERT_OK_EQ(parse_errno("4095"), 4095);

        ASSERT_ERROR(parse_errno("-1"), ERANGE);
        ASSERT_ERROR(parse_errno("-3"), ERANGE);
        ASSERT_ERROR(parse_errno("4096"), ERANGE);

        ASSERT_ERROR(parse_errno(""), EINVAL);
        ASSERT_ERROR(parse_errno("12.3"), EINVAL);
        ASSERT_ERROR(parse_errno("123junk"), EINVAL);
        ASSERT_ERROR(parse_errno("junk123"), EINVAL);
        ASSERT_ERROR(parse_errno("255EILSEQ"), EINVAL);
        ASSERT_ERROR(parse_errno("EINVAL12"), EINVAL);
        ASSERT_ERROR(parse_errno("-EINVAL"), EINVAL);
        ASSERT_ERROR(parse_errno("EINVALaaa"), EINVAL);
}

TEST(parse_fd) {
        ASSERT_OK_EQ(parse_fd("0"), 0);
        ASSERT_OK_EQ(parse_fd("1"), 1);

        ASSERT_ERROR(parse_fd("-1"), EBADF);
        ASSERT_ERROR(parse_fd("-3"), EBADF);

        ASSERT_ERROR(parse_fd(""), EINVAL);
        ASSERT_ERROR(parse_fd("12.3"), EINVAL);
        ASSERT_ERROR(parse_fd("123junk"), EINVAL);
        ASSERT_ERROR(parse_fd("junk123"), EINVAL);
}

TEST(parse_mtu) {
        uint32_t mtu = 0;

        ASSERT_OK(parse_mtu(AF_UNSPEC, "1500", &mtu));
        ASSERT_EQ(mtu, 1500U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "1400", &mtu));
        ASSERT_EQ(mtu, 1400U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "65535", &mtu));
        ASSERT_EQ(mtu, 65535U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "65536", &mtu));
        ASSERT_EQ(mtu, 65536U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "4294967295", &mtu));
        ASSERT_EQ(mtu, 4294967295U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "500", &mtu));
        ASSERT_EQ(mtu, 500U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "1280", &mtu));
        ASSERT_EQ(mtu, 1280U);

        ASSERT_ERROR(parse_mtu(AF_UNSPEC, "4294967296", &mtu), ERANGE);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "68", &mtu));
        ASSERT_EQ(mtu, 68U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "67", &mtu));
        ASSERT_EQ(mtu, 67U);

        ASSERT_OK(parse_mtu(AF_UNSPEC, "0", &mtu));
        ASSERT_EQ(mtu, 0U);

        ASSERT_ERROR(parse_mtu(AF_UNSPEC, "", &mtu), EINVAL);

        ASSERT_OK(parse_mtu(AF_INET, "1500", &mtu));
        ASSERT_EQ(mtu, 1500U);

        ASSERT_OK(parse_mtu(AF_INET, "1400", &mtu));
        ASSERT_EQ(mtu, 1400U);

        ASSERT_OK(parse_mtu(AF_INET, "65535", &mtu));
        ASSERT_EQ(mtu, 65535U);

        ASSERT_OK(parse_mtu(AF_INET, "65536", &mtu));
        ASSERT_EQ(mtu, 65536U);

        ASSERT_OK(parse_mtu(AF_INET, "4294967295", &mtu));
        ASSERT_EQ(mtu, 4294967295U);

        ASSERT_OK(parse_mtu(AF_INET, "500", &mtu));
        ASSERT_EQ(mtu, 500U);

        ASSERT_OK(parse_mtu(AF_INET, "1280", &mtu));
        ASSERT_EQ(mtu, 1280U);

        ASSERT_ERROR(parse_mtu(AF_INET, "4294967296", &mtu), ERANGE);

        ASSERT_OK(parse_mtu(AF_INET, "68", &mtu));
        ASSERT_EQ(mtu, 68U);

        ASSERT_ERROR(parse_mtu(AF_INET, "67", &mtu), ERANGE);
        ASSERT_ERROR(parse_mtu(AF_INET, "0", &mtu), ERANGE);
        ASSERT_ERROR(parse_mtu(AF_INET, "", &mtu), EINVAL);

        ASSERT_OK(parse_mtu(AF_INET6, "1280", &mtu));
        ASSERT_EQ(mtu, 1280U);

        ASSERT_ERROR(parse_mtu(AF_INET6, "1279", &mtu), ERANGE);
        ASSERT_ERROR(parse_mtu(AF_INET6, "4294967296", &mtu), ERANGE);
        ASSERT_ERROR(parse_mtu(AF_INET6, "68", &mtu), ERANGE);
        ASSERT_ERROR(parse_mtu(AF_INET6, "", &mtu), EINVAL);
}

TEST(parse_loadavg_fixed_point) {
        loadavg_t fp;

        ASSERT_OK_ZERO(parse_loadavg_fixed_point("1.23", &fp));
        ASSERT_EQ(LOADAVG_INT_SIDE(fp), 1U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(fp), 23U);

        ASSERT_OK_ZERO(parse_loadavg_fixed_point("1.80", &fp));
        ASSERT_EQ(LOADAVG_INT_SIDE(fp), 1U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(fp), 80U);

        ASSERT_OK_ZERO(parse_loadavg_fixed_point("0.07", &fp));
        ASSERT_EQ(LOADAVG_INT_SIDE(fp), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(fp), 7U);

        ASSERT_OK_ZERO(parse_loadavg_fixed_point("0.00", &fp));
        ASSERT_EQ(LOADAVG_INT_SIDE(fp), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(fp), 0U);

        ASSERT_OK_ZERO(parse_loadavg_fixed_point("4096.57", &fp));
        ASSERT_EQ(LOADAVG_INT_SIDE(fp), 4096U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(fp), 57U);

        /* Caps out at 2 digit fracs */
        ASSERT_ERROR(parse_loadavg_fixed_point("1.100", &fp), ERANGE);

        ASSERT_ERROR(parse_loadavg_fixed_point("4096.4096", &fp), ERANGE);
        ASSERT_ERROR(parse_loadavg_fixed_point("-4000.5", &fp), ERANGE);
        ASSERT_ERROR(parse_loadavg_fixed_point("18446744073709551615.5", &fp), ERANGE);
        ASSERT_ERROR(parse_loadavg_fixed_point("foobar", &fp), EINVAL);
        ASSERT_ERROR(parse_loadavg_fixed_point("3333", &fp), EINVAL);
        ASSERT_ERROR(parse_loadavg_fixed_point("1.2.3", &fp), EINVAL);
        ASSERT_ERROR(parse_loadavg_fixed_point(".", &fp), EINVAL);
        ASSERT_ERROR(parse_loadavg_fixed_point("", &fp), EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
