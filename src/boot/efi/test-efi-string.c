/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "tests.h"

TEST(strlen8) {
        assert_se(strlen8(NULL) == 0);
        assert_se(strlen8("") == 0);
        assert_se(strlen8("1") == 1);
        assert_se(strlen8("11") == 2);
        assert_se(strlen8("123456789") == 9);
        assert_se(strlen8("12\0004") == 2);
}

TEST(strlen16) {
        assert_se(strlen16(NULL) == 0);
        assert_se(strlen16(u"") == 0);
        assert_se(strlen16(u"1") == 1);
        assert_se(strlen16(u"11") == 2);
        assert_se(strlen16(u"123456789") == 9);
        assert_se(strlen16(u"12\0004") == 2);
}

TEST(strnlen8) {
        assert_se(strnlen8(NULL, 0) == 0);
        assert_se(strnlen8(NULL, 10) == 0);
        assert_se(strnlen8("", 10) == 0);
        assert_se(strnlen8("1", 10) == 1);
        assert_se(strnlen8("11", 1) == 1);
        assert_se(strnlen8("123456789", 7) == 7);
        assert_se(strnlen8("12\0004", 5) == 2);
}

TEST(strnlen16) {
        assert_se(strnlen16(NULL, 0) == 0);
        assert_se(strnlen16(NULL, 10) == 0);
        assert_se(strnlen16(u"", 10) == 0);
        assert_se(strnlen16(u"1", 10) == 1);
        assert_se(strnlen16(u"11", 1) == 1);
        assert_se(strnlen16(u"123456789", 7) == 7);
        assert_se(strnlen16(u"12\0004", 5) == 2);
}

TEST(strncmp8) {
        assert_se(strncmp8(NULL, "", 10) < 0);
        assert_se(strncmp8("", NULL, 10) > 0);
        assert_se(strncmp8(NULL, NULL, 0) == 0);
        assert_se(strncmp8(NULL, NULL, 10) == 0);
        assert_se(strncmp8("", "", 10) == 0);
        assert_se(strncmp8("abc", "abc", 2) == 0);
        assert_se(strncmp8("aBc", "aBc", 3) == 0);
        assert_se(strncmp8("aBC", "aBC", 4) == 0);
        assert_se(strncmp8("", "a", 0) == 0);
        assert_se(strncmp8("b", "a", 0) == 0);
        assert_se(strncmp8("", "a", 3) < 0);
        assert_se(strncmp8("=", "=", 1) == 0);
        assert_se(strncmp8("A", "a", 1) < 0);
        assert_se(strncmp8("a", "A", 2) > 0);
        assert_se(strncmp8("a", "Aa", 2) > 0);
        assert_se(strncmp8("12\00034", "12345", 4) < 0);
        assert_se(strncmp8("12\00034", "12345", SIZE_MAX) < 0);
        assert_se(strncmp8("abc\0def", "abc", SIZE_MAX) == 0);
        assert_se(strncmp8("abc\0def", "abcdef", SIZE_MAX) < 0);

        assert_se(strncmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MIN }, 1) == 0);
        assert_se(strncmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MAX }, 1) == 0);
        assert_se(strncmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MAX }, 1) < 0);
        assert_se(strncmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MIN }, 1) > 0);
}

TEST(strncmp16) {
        assert_se(strncmp16(NULL, u"", 10) < 0);
        assert_se(strncmp16(u"", NULL, 10) > 0);
        assert_se(strncmp16(NULL, NULL, 0) == 0);
        assert_se(strncmp16(NULL, NULL, 10) == 0);
        assert_se(strncmp16(u"", u"", 0) == 0);
        assert_se(strncmp16(u"", u"", 10) == 0);
        assert_se(strncmp16(u"abc", u"abc", 2) == 0);
        assert_se(strncmp16(u"aBc", u"aBc", 3) == 0);
        assert_se(strncmp16(u"aBC", u"aBC", 4) == 0);
        assert_se(strncmp16(u"", u"a", 0) == 0);
        assert_se(strncmp16(u"b", u"a", 0) == 0);
        assert_se(strncmp16(u"", u"a", 3) < 0);
        assert_se(strncmp16(u"=", u"=", 1) == 0);
        assert_se(strncmp16(u"A", u"a", 1) < 0);
        assert_se(strncmp16(u"a", u"A", 2) > 0);
        assert_se(strncmp16(u"a", u"Aa", 2) > 0);
        assert_se(strncmp16(u"12\00034", u"12345", 4) < 0);
        assert_se(strncmp16(u"12\00034", u"12345", SIZE_MAX) < 0);
        assert_se(strncmp16(u"abc\0def", u"abc", SIZE_MAX) == 0);
        assert_se(strncmp16(u"abc\0def", u"abcdef", SIZE_MAX) < 0);

        assert_se(strncmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ UINT16_MAX }, 1) == 0);
        assert_se(strncmp16((char16_t[]){ 0 }, (char16_t[]){ UINT16_MAX }, 1) < 0);
        assert_se(strncmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ 0 }, 1) > 0);
}

TEST(strncasecmp8) {
        assert_se(strncasecmp8(NULL, "", 10) < 0);
        assert_se(strncasecmp8("", NULL, 10) > 0);
        assert_se(strncasecmp8(NULL, NULL, 0) == 0);
        assert_se(strncasecmp8(NULL, NULL, 10) == 0);
        assert_se(strncasecmp8("", "", 10) == 0);
        assert_se(strncasecmp8("abc", "abc", 2) == 0);
        assert_se(strncasecmp8("aBc", "AbC", 3) == 0);
        assert_se(strncasecmp8("aBC", "Abc", 4) == 0);
        assert_se(strncasecmp8("", "a", 0) == 0);
        assert_se(strncasecmp8("b", "a", 0) == 0);
        assert_se(strncasecmp8("", "a", 3) < 0);
        assert_se(strncasecmp8("=", "=", 1) == 0);
        assert_se(strncasecmp8("A", "a", 1) == 0);
        assert_se(strncasecmp8("a", "A", 2) == 0);
        assert_se(strncasecmp8("a", "Aa", 2) < 0);
        assert_se(strncasecmp8("12\00034", "12345", 4) < 0);
        assert_se(strncasecmp8("12\00034", "12345", SIZE_MAX) < 0);
        assert_se(strncasecmp8("abc\0def", "ABC", SIZE_MAX) == 0);
        assert_se(strncasecmp8("abc\0def", "ABCDEF", SIZE_MAX) < 0);

        assert_se(strncasecmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MIN }, 1) == 0);
        assert_se(strncasecmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MAX }, 1) == 0);
        assert_se(strncasecmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MAX }, 1) < 0);
        assert_se(strncasecmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MIN }, 1) > 0);
}

TEST(strncasecmp16) {
        assert_se(strncasecmp16(NULL, u"", 10) < 0);
        assert_se(strncasecmp16(u"", NULL, 10) > 0);
        assert_se(strncasecmp16(NULL, NULL, 0) == 0);
        assert_se(strncasecmp16(NULL, NULL, 10) == 0);
        assert_se(strncasecmp16(u"", u"", 10) == 0);
        assert_se(strncasecmp16(u"abc", u"abc", 2) == 0);
        assert_se(strncasecmp16(u"aBc", u"AbC", 3) == 0);
        assert_se(strncasecmp16(u"aBC", u"Abc", 4) == 0);
        assert_se(strncasecmp16(u"", u"a", 0) == 0);
        assert_se(strncasecmp16(u"b", u"a", 0) == 0);
        assert_se(strncasecmp16(u"", u"a", 3) < 0);
        assert_se(strncasecmp16(u"=", u"=", 1) == 0);
        assert_se(strncasecmp16(u"A", u"a", 1) == 0);
        assert_se(strncasecmp16(u"a", u"A", 2) == 0);
        assert_se(strncasecmp16(u"a", u"Aa", 2) < 0);
        assert_se(strncasecmp16(u"12\00034", u"12345", 4) < 0);
        assert_se(strncasecmp16(u"12\00034", u"12345", SIZE_MAX) < 0);
        assert_se(strncasecmp16(u"abc\0def", u"ABC", SIZE_MAX) == 0);
        assert_se(strncasecmp16(u"abc\0def", u"ABCDEF", SIZE_MAX) < 0);

        assert_se(strncasecmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ UINT16_MAX }, 1) == 0);
        assert_se(strncasecmp16((char16_t[]){ 0 }, (char16_t[]){ UINT16_MAX }, 1) < 0);
        assert_se(strncasecmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ 0 }, 1) > 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
