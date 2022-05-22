/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"
#include "uchar.h"

/* Do some basic checks on STRLEN() and DECIMAL_STR_MAX() */
assert_cc(STRLEN("") == 0);
assert_cc(STRLEN("a") == 1);
assert_cc(STRLEN("123") == 3);
assert_cc(STRLEN(u8"") == 0);
assert_cc(STRLEN(u8"a") == 1);
assert_cc(STRLEN(u8"123") == 3);
assert_cc(STRLEN(u"") == 0);
assert_cc(STRLEN(u"a") == sizeof(char16_t));
assert_cc(STRLEN(u"123") == 3 * sizeof(char16_t));
assert_cc(STRLEN(U"") == 0);
assert_cc(STRLEN(U"a") == sizeof(char32_t));
assert_cc(STRLEN(U"123") == 3 * sizeof(char32_t));
assert_cc(STRLEN(L"") == 0);
assert_cc(STRLEN(L"a") == sizeof(wchar_t));
assert_cc(STRLEN(L"123") == 3 * sizeof(wchar_t));
assert_cc(DECIMAL_STR_MAX(uint8_t) == STRLEN("255")+1);
assert_cc(DECIMAL_STR_MAX(int8_t) == STRLEN("-127")+1);
assert_cc(DECIMAL_STR_MAX(uint64_t) == STRLEN("18446744073709551615")+1);
assert_cc(DECIMAL_STR_MAX(int64_t) == CONST_MAX(STRLEN("-9223372036854775808"), STRLEN("9223372036854775807"))+1);
assert_cc(DECIMAL_STR_MAX(signed char) == STRLEN("-127")+1);
assert_cc(DECIMAL_STR_MAX(unsigned char) == STRLEN("255")+1);
assert_cc(CONST_MAX(DECIMAL_STR_MAX(int8_t), STRLEN("xxx")) == 5);

static void test_format_bytes_one(uint64_t val, bool trailing_B, const char *iec_with_p, const char *iec_without_p,
                                  const char *si_with_p, const char *si_without_p) {
        char buf[FORMAT_BYTES_MAX];

        assert_se(streq_ptr(format_bytes_full(buf, sizeof buf, val, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | (trailing_B ? FORMAT_BYTES_TRAILING_B : 0)), iec_with_p));
        assert_se(streq_ptr(format_bytes_full(buf, sizeof buf, val, FORMAT_BYTES_USE_IEC | (trailing_B ? FORMAT_BYTES_TRAILING_B : 0)), iec_without_p));
        assert_se(streq_ptr(format_bytes_full(buf, sizeof buf, val, FORMAT_BYTES_BELOW_POINT | (trailing_B ? FORMAT_BYTES_TRAILING_B : 0)), si_with_p));
        assert_se(streq_ptr(format_bytes_full(buf, sizeof buf, val, trailing_B ? FORMAT_BYTES_TRAILING_B : 0), si_without_p));
}

TEST(format_bytes) {
        test_format_bytes_one(900, true, "900B", "900B", "900B", "900B");
        test_format_bytes_one(900, false, "900", "900", "900", "900");
        test_format_bytes_one(1023, true, "1023B", "1023B", "1.0K", "1K");
        test_format_bytes_one(1023, false, "1023", "1023", "1.0K", "1K");
        test_format_bytes_one(1024, true, "1.0K", "1K", "1.0K", "1K");
        test_format_bytes_one(1024, false, "1.0K", "1K", "1.0K", "1K");
        test_format_bytes_one(1100, true, "1.0K", "1K", "1.1K", "1K");
        test_format_bytes_one(1500, true, "1.4K", "1K", "1.5K", "1K");
        test_format_bytes_one(UINT64_C(3)*1024*1024, true, "3.0M", "3M", "3.1M", "3M");
        test_format_bytes_one(UINT64_C(3)*1024*1024*1024, true, "3.0G", "3G", "3.2G", "3G");
        test_format_bytes_one(UINT64_C(3)*1024*1024*1024*1024, true, "3.0T", "3T", "3.2T", "3T");
        test_format_bytes_one(UINT64_C(3)*1024*1024*1024*1024*1024, true, "3.0P", "3P", "3.3P", "3P");
        test_format_bytes_one(UINT64_C(3)*1024*1024*1024*1024*1024*1024, true, "3.0E", "3E", "3.4E", "3E");
        test_format_bytes_one(UINT64_MAX, true, NULL, NULL, NULL, NULL);
        test_format_bytes_one(UINT64_MAX, false, NULL, NULL, NULL, NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
