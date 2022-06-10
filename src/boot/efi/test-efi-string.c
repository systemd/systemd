/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

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

TEST(strsize8) {
        assert_se(strsize8(NULL) == 0);
        assert_se(strsize8("") == 1);
        assert_se(strsize8("1") == 2);
        assert_se(strsize8("11") == 3);
        assert_se(strsize8("123456789") == 10);
        assert_se(strsize8("12\0004") == 3);
}

TEST(strsize16) {
        assert_se(strsize16(NULL) == 0);
        assert_se(strsize16(u"") == 2);
        assert_se(strsize16(u"1") == 4);
        assert_se(strsize16(u"11") == 6);
        assert_se(strsize16(u"123456789") == 20);
        assert_se(strsize16(u"12\0004") == 6);
}

TEST(strtolower8) {
        char s[] = "\0001234abcDEF!\0zZ";

        strtolower8(NULL);

        strtolower8(s);
        assert_se(memcmp(s, "\0001234abcDEF!\0zZ", sizeof(s)) == 0);

        s[0] = '#';
        strtolower8(s);
        assert_se(memcmp(s, "#1234abcdef!\0zZ", sizeof(s)) == 0);
}

TEST(strtolower16) {
        char16_t s[] = u"\0001234abcDEF!\0zZ";

        strtolower16(NULL);

        strtolower16(s);
        assert_se(memcmp(s, u"\0001234abcDEF!\0zZ", sizeof(s)) == 0);

        s[0] = '#';
        strtolower16(s);
        assert_se(memcmp(s, u"#1234abcdef!\0zZ", sizeof(s)) == 0);
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

TEST(strcpy8) {
        char buf[128];

        assert_se(strcpy8(buf, "123") == buf);
        assert_se(streq8(buf, "123"));
        assert_se(strcpy8(buf, "") == buf);
        assert_se(streq8(buf, ""));
        assert_se(strcpy8(buf, "A") == buf);
        assert_se(streq8(buf, "A"));
        assert_se(strcpy8(buf, NULL) == buf);
        assert_se(streq8(buf, ""));
}

TEST(strcpy16) {
        char16_t buf[128];

        assert_se(strcpy16(buf, u"123") == buf);
        assert_se(streq16(buf, u"123"));
        assert_se(strcpy16(buf, u"") == buf);
        assert_se(streq16(buf, u""));
        assert_se(strcpy16(buf, u"A") == buf);
        assert_se(streq16(buf, u"A"));
        assert_se(strcpy16(buf, NULL) == buf);
        assert_se(streq16(buf, u""));
}

TEST(strchr8) {
        assert_se(!strchr8(NULL, 'a'));
        assert_se(!strchr8("", 'a'));
        assert_se(!strchr8("123", 'a'));

        const char str[] = "abcaBc";
        assert_se(strchr8(str, 'a') == &str[0]);
        assert_se(strchr8(str, 'c') == &str[2]);
        assert_se(strchr8(str, 'B') == &str[4]);
}

TEST(strchr16) {
        assert_se(!strchr16(NULL, 'a'));
        assert_se(!strchr16(u"", 'a'));
        assert_se(!strchr16(u"123", 'a'));

        const char16_t str[] = u"abcaBc";
        assert_se(strchr16(str, 'a') == &str[0]);
        assert_se(strchr16(str, 'c') == &str[2]);
        assert_se(strchr16(str, 'B') == &str[4]);
}

TEST(xstrndup8) {
        char *s = NULL;

        assert_se(xstrndup8(NULL, 0) == NULL);
        assert_se(xstrndup8(NULL, 10) == NULL);

        assert_se(s = xstrndup8("", 10));
        assert_se(streq8(s, ""));
        free(s);

        assert_se(s = xstrndup8("abc", 0));
        assert_se(streq8(s, ""));
        free(s);

        assert_se(s = xstrndup8("ABC", 3));
        assert_se(streq8(s, "ABC"));
        free(s);

        assert_se(s = xstrndup8("123abcDEF", 5));
        assert_se(streq8(s, "123ab"));
        free(s);
}

TEST(xstrdup8) {
        char *s = NULL;

        assert_se(xstrdup8(NULL) == NULL);

        assert_se(s = xstrdup8(""));
        assert_se(streq8(s, ""));
        free(s);

        assert_se(s = xstrdup8("1"));
        assert_se(streq8(s, "1"));
        free(s);

        assert_se(s = xstrdup8("123abcDEF"));
        assert_se(streq8(s, "123abcDEF"));
        free(s);
}

TEST(xstrndup16) {
        char16_t *s = NULL;

        assert_se(xstrndup16(NULL, 0) == NULL);
        assert_se(xstrndup16(NULL, 10) == NULL);

        assert_se(s = xstrndup16(u"", 10));
        assert_se(streq16(s, u""));
        free(s);

        assert_se(s = xstrndup16(u"abc", 0));
        assert_se(streq16(s, u""));
        free(s);

        assert_se(s = xstrndup16(u"ABC", 3));
        assert_se(streq16(s, u"ABC"));
        free(s);

        assert_se(s = xstrndup16(u"123abcDEF", 5));
        assert_se(streq16(s, u"123ab"));
        free(s);
}

TEST(xstrdup16) {
        char16_t *s = NULL;

        assert_se(xstrdup16(NULL) == NULL);

        assert_se(s = xstrdup16(u""));
        assert_se(streq16(s, u""));
        free(s);

        assert_se(s = xstrdup16(u"1"));
        assert_se(streq16(s, u"1"));
        free(s);

        assert_se(s = xstrdup16(u"123abcDEF"));
        assert_se(streq16(s, u"123abcDEF"));
        free(s);
}

#define TEST_FNMATCH_ONE(pattern, haystack, expect)                                     \
        ({                                                                              \
                assert_se(fnmatch(pattern, haystack, 0) == (expect ? 0 : FNM_NOMATCH)); \
                assert_se(efi_fnmatch(u##pattern, u##haystack) == expect);              \
        })

TEST(efi_fnmatch) {
        TEST_FNMATCH_ONE("", "", true);
        TEST_FNMATCH_ONE("abc", "abc", true);
        TEST_FNMATCH_ONE("aBc", "abc", false);
        TEST_FNMATCH_ONE("b", "a", false);
        TEST_FNMATCH_ONE("b", "", false);
        TEST_FNMATCH_ONE("abc", "a", false);
        TEST_FNMATCH_ONE("a?c", "azc", true);
        TEST_FNMATCH_ONE("???", "?.9", true);
        TEST_FNMATCH_ONE("1?", "1", false);
        TEST_FNMATCH_ONE("***", "", true);
        TEST_FNMATCH_ONE("*", "123", true);
        TEST_FNMATCH_ONE("**", "abcd", true);
        TEST_FNMATCH_ONE("*b*", "abcd", true);
        TEST_FNMATCH_ONE("abc*d", "abc", false);
        TEST_FNMATCH_ONE("*.conf", "arch.conf", true);
        TEST_FNMATCH_ONE("debian-*.conf", "debian-wheezy.conf", true);
        TEST_FNMATCH_ONE("debian-*.*", "debian-wheezy.efi", true);
        TEST_FNMATCH_ONE("ab*cde", "abzcd", false);
        TEST_FNMATCH_ONE("\\*\\a\\[", "*a[", true);
        TEST_FNMATCH_ONE("[abc] [abc] [abc]", "a b c", true);
        TEST_FNMATCH_ONE("abc]", "abc]", true);
        TEST_FNMATCH_ONE("[abc]", "z", false);
        TEST_FNMATCH_ONE("[abc", "a", false);
        TEST_FNMATCH_ONE("[][!] [][!] [][!]", "[ ] !", true);
        TEST_FNMATCH_ONE("[]-] []-]", "] -", true);
        TEST_FNMATCH_ONE("[1\\]] [1\\]]", "1 ]", true);
        TEST_FNMATCH_ONE("[$-\\+]", "&", true);
        TEST_FNMATCH_ONE("[1-3A-C] [1-3A-C]", "2 B", true);
        TEST_FNMATCH_ONE("[3-5] [3-5] [3-5]", "3 4 5", true);
        TEST_FNMATCH_ONE("[f-h] [f-h] [f-h]", "f g h", true);
        TEST_FNMATCH_ONE("[a-c-f] [a-c-f] [a-c-f] [a-c-f] [a-c-f]", "a b c - f", true);
        TEST_FNMATCH_ONE("[a-c-f]", "e", false);
        TEST_FNMATCH_ONE("[--0] [--0] [--0]", "- . 0", true);
        TEST_FNMATCH_ONE("[+--] [+--] [+--]", "+ , -", true);
        TEST_FNMATCH_ONE("[f-l]", "m", false);
        TEST_FNMATCH_ONE("[b]", "z-a", false);
        TEST_FNMATCH_ONE("[a\\-z]", "b", false);
        TEST_FNMATCH_ONE("?a*b[.-0]c", "/a/b/c", true);
}

TEST(parse_number8) {
        uint64_t u;
        const char *tail;

        assert_se(!parse_number8(NULL, &u, NULL));
        assert_se(!parse_number8("", &u, NULL));
        assert_se(!parse_number8("a1", &u, NULL));
        assert_se(!parse_number8("1a", &u, NULL));
        assert_se(!parse_number8("-42", &u, NULL));
        assert_se(!parse_number8("18446744073709551616", &u, NULL));

        assert_se(parse_number8("0", &u, NULL));
        assert_se(u == 0);
        assert_se(parse_number8("1", &u, NULL));
        assert_se(u == 1);
        assert_se(parse_number8("999", &u, NULL));
        assert_se(u == 999);
        assert_se(parse_number8("18446744073709551615", &u, NULL));
        assert_se(u == UINT64_MAX);
        assert_se(parse_number8("42", &u, &tail));
        assert_se(u == 42);
        assert_se(streq8(tail, ""));
        assert_se(parse_number8("54321rest", &u, &tail));
        assert_se(u == 54321);
        assert_se(streq8(tail, "rest"));
}

TEST(parse_number16) {
        uint64_t u;
        const char16_t *tail;

        assert_se(!parse_number16(NULL, &u, NULL));
        assert_se(!parse_number16(u"", &u, NULL));
        assert_se(!parse_number16(u"a1", &u, NULL));
        assert_se(!parse_number16(u"1a", &u, NULL));
        assert_se(!parse_number16(u"-42", &u, NULL));
        assert_se(!parse_number16(u"18446744073709551616", &u, NULL));

        assert_se(parse_number16(u"0", &u, NULL));
        assert_se(u == 0);
        assert_se(parse_number16(u"1", &u, NULL));
        assert_se(u == 1);
        assert_se(parse_number16(u"999", &u, NULL));
        assert_se(u == 999);
        assert_se(parse_number16(u"18446744073709551615", &u, NULL));
        assert_se(u == UINT64_MAX);
        assert_se(parse_number16(u"42", &u, &tail));
        assert_se(u == 42);
        assert_se(streq16(tail, u""));
        assert_se(parse_number16(u"54321rest", &u, &tail));
        assert_se(u == 54321);
        assert_se(streq16(tail, u"rest"));
}

_printf_(1, 2) static void test_vsnprintf_status_one(const char *format, ...) {
        va_list ap, ap_efi, ap_efi2;
        va_start(ap, format);
        va_copy(ap_efi, ap);
        va_copy(ap_efi2, ap);

        _cleanup_free_ char *buf = NULL;
        int r = vasprintf(&buf, format, ap);
        assert_se(r >= 0);
        log_info("/* %s(%s) -> \"%.100s\" */", __func__, format, buf);

        char16_t buf_efi[r + 1];
        int r_efi = vsnprintf_status(0, buf_efi, r + 1, format, ap_efi);

        bool eq = true;
        for (size_t i = 0; i < (size_t) r; i++) {
                if (buf[i] != buf_efi[i])
                        eq = false;
                buf[i] = buf_efi[i];
        }

        log_info("%.100s", buf);
        assert_se(eq);
        assert_se(r == r_efi);

        /* Also test dynmic allocation variant. */
        _cleanup_free_ char16_t *buf_efi_dyn = xvasprintf_status(0, format, ap_efi2);
        assert_se(streq16(buf_efi, buf_efi_dyn));

        va_end(ap);
        va_end(ap_efi);
        va_end(ap_efi2);
}

TEST(vsnprintf_status) {
        test_vsnprintf_status_one("nothing");
        test_vsnprintf_status_one("%% still nothing %%%%");

        test_vsnprintf_status_one("%p %p", NULL, &(int){ 0 });

        test_vsnprintf_status_one("%c %c %c", '1', '!', '~');
        test_vsnprintf_status_one("%lc %lc %lc", L'1', L'!', L'~');

        test_vsnprintf_status_one("%s %s %s", "123456", "abc", "def");
        test_vsnprintf_status_one("%.4s %.4s %.4s", "123456", "1234", "12");
        test_vsnprintf_status_one("%8s %8s %8s", "123456", "1234", "12");
        test_vsnprintf_status_one("%8.4s %8.4s %8.4s", "123456", "1234", "12");

        test_vsnprintf_status_one("%.*s %.*s %.*s", 4, "123456", 4, "1234", 4, "12");
        test_vsnprintf_status_one("%*s %*s %*s", 8, "123456", 8, "1234", 8, "12");
        test_vsnprintf_status_one("%*.*s %*.*s %*.*s", 8, 4, "123456", 8, 4, "1234", 8, 4, "12");

        test_vsnprintf_status_one("%ls %ls %ls", L"123456", L"abc", L"def");
        test_vsnprintf_status_one("%.4ls %.4ls %.4ls", L"123456", L"1234", L"12");
        test_vsnprintf_status_one("%8ls %8ls %8ls", L"123456", L"1234", L"12");
        test_vsnprintf_status_one("%8.4ls %8.4ls %8.4ls", L"123456", L"1234", L"12");

        test_vsnprintf_status_one("%.*ls %.*ls %.*ls", 4, L"123456", 4, L"1234", 4, L"12");
        test_vsnprintf_status_one("%*ls %*ls %*ls", 8, L"123456", 8, L"1234", 8, L"12");
        test_vsnprintf_status_one("%*.*ls %*.*ls %*.*ls", 8, 4, L"123456", 8, 4, L"1234", 8, 4, L"12");

        test_vsnprintf_status_one("%u %u %u", 0, 42, 1234567890);
        test_vsnprintf_status_one("%i %i %i", 0, -42, -1234567890);
        test_vsnprintf_status_one("%x %x %x", 0x0, 0x42, 0x123ABC);
        test_vsnprintf_status_one("%X %X %X", 0X1, 0X43, 0X234BCD);
        test_vsnprintf_status_one("%#x %#x %#x", 0x2, 0x44, 0x345CDE);
        test_vsnprintf_status_one("%#X %#X %#X", 0X3, 0X45, 0X456FED);

        test_vsnprintf_status_one("%u %u %zu", INT_MIN, INT_MAX, SIZE_MAX);
        test_vsnprintf_status_one("%i %i %zi", INT_MIN, INT_MAX, SIZE_MAX);
        test_vsnprintf_status_one("%x %x %zx", INT_MIN, INT_MAX, SIZE_MAX);
        test_vsnprintf_status_one("%X %X %zX", INT_MIN, INT_MAX, SIZE_MAX);
        test_vsnprintf_status_one("%#x %#x %#zx", INT_MIN, INT_MAX, SIZE_MAX);
        test_vsnprintf_status_one("%#X %#X %#zX", INT_MIN, INT_MAX, SIZE_MAX);

        test_vsnprintf_status_one("%" PRIi64 " %" PRIi64 " %" PRIi64, UINT64_MAX, INT64_MIN, INT64_MAX);
        test_vsnprintf_status_one("%" PRIu64 " %" PRIu64 " %" PRIu64, UINT64_MAX, INT64_MIN, INT64_MAX);
        test_vsnprintf_status_one("%" PRIx64 " %" PRIx64 " %" PRIx64, UINT64_MAX, INT64_MIN, INT64_MAX);
        test_vsnprintf_status_one("%" PRIX64 " %" PRIX64 " %" PRIX64, UINT64_MAX, INT64_MIN, INT64_MAX);
        test_vsnprintf_status_one("%#" PRIx64 " %#" PRIx64 " %#" PRIx64, UINT64_MAX, INT64_MIN, INT64_MAX);
        test_vsnprintf_status_one("%#" PRIX64 " %#" PRIX64 " %#" PRIX64, UINT64_MAX, INT64_MIN, INT64_MAX);

        test_vsnprintf_status_one("%.11u %.11i %.11x %.11X %#.11x %#.11X", 4, 5, 6, 0xA, 0xB, 0xC);
        test_vsnprintf_status_one("%.11u %.11i %.11x %.11X %#.11x %#.11X", -4, -5, -6, -0xA, -0xB, -0xC);
        test_vsnprintf_status_one("%13u %13i %13x %13X %#13x %#13X", 4, 5, 6, 0xA, 0xB, 0xC);
        test_vsnprintf_status_one("%13u %13i %13x %13X %#13x %#13X", -4, -5, -6, -0xA, -0xB, -0xC);
        test_vsnprintf_status_one("%8.4u %8.4i %8.4x %8.4X %#8.4x %#8.4X", 4, 5, 6, 0xA, 0xB, 0xC);
        test_vsnprintf_status_one("%8.4u %8.4i %8.4x %8.4X %#8.4x %#8.4X", -4, -5, -6, -0xA, -0xB, -0xC);
        test_vsnprintf_status_one("%08u %08i %08x %08X %#08x %#08X", 4, 5, 6, 0xA, 0xB, 0xC);

        test_vsnprintf_status_one("%.*u %.*i %.*x", 15, 42, 15, 42, 15, 42);
        test_vsnprintf_status_one("%.*X %#.*x %#.*X", 15, 42, 15, 42, 15, 42);
        test_vsnprintf_status_one("%*u %*i %*x", 15, 42, 15, 42, 15, 42);
        test_vsnprintf_status_one("%*X %#*x %#*X", 15, 42, 15, 42, 15, 42);
        test_vsnprintf_status_one("%*.*u %*.*i %*.*x", 15, 15, 42, 15, 15, 42, 15, 15, 42);
        test_vsnprintf_status_one("%*.*X %#*.*x %#*.*X", 15, 15, 42, 15, 15, 42, 15, 15, 42);

        /* Test buf size grow. */
        test_vsnprintf_status_one("%0*u", PRINTF_BUF_SIZE * 4, 42);

        /* Buffer too small. */
        assert_se(snprintf_status(0, (char16_t[3]){}, 3, "0123456") == -1);
        assert_se(snprintf_status(0, (char16_t[3]){}, 3, "%s", "abcdefg") == -1);

        /* Non vsnprintf-compatible behavior tests below. */
        char16_t buf[9];

        /* EFI Status codes. */
        assert_se(snprintf_status(0, buf, ELEMENTSOF(buf), "%m") == 8);
        assert_se(streq16(buf, u"0x000000"));
        assert_se(snprintf_status(0x42, buf, ELEMENTSOF(buf), "%m") == 8);
        assert_se(streq16(buf, u"0x000042"));

        /* New line translation. */
        assert_se(snprintf_status(0, buf, ELEMENTSOF(buf), "\n \r\n") == 5);
        assert_se(streq16(buf, u"\r\n \r\n"));
}

TEST(efi_memcmp) {
        assert_se(efi_memcmp(NULL, NULL, 0) == 0);
        assert_se(efi_memcmp(NULL, NULL, 1) == 0);
        assert_se(efi_memcmp(NULL, "", 1) < 0);
        assert_se(efi_memcmp("", NULL, 1) > 0);
        assert_se(efi_memcmp("", "", 0) == 0);
        assert_se(efi_memcmp("", "", 1) == 0);
        assert_se(efi_memcmp("1", "1", 1) == 0);
        assert_se(efi_memcmp("1", "2", 1) < 0);
        assert_se(efi_memcmp("A", "a", 1) < 0);
        assert_se(efi_memcmp("a", "A", 1) > 0);
        assert_se(efi_memcmp("abc", "ab", 2) == 0);
        assert_se(efi_memcmp("ab", "abc", 3) < 0);
        assert_se(efi_memcmp("abc", "ab", 3) > 0);
        assert_se(efi_memcmp("ab\000bd", "ab\000bd", 6) == 0);
        assert_se(efi_memcmp("ab\000b\0", "ab\000bd", 6) < 0);
}

TEST(efi_memcpy) {
        char buf[10];

        assert_se(!efi_memcpy(NULL, NULL, 0));
        assert_se(!efi_memcpy(NULL, "", 1));
        assert_se(efi_memcpy(buf, NULL, 0) == buf);
        assert_se(efi_memcpy(buf, NULL, 1) == buf);
        assert_se(efi_memcpy(buf, "a", 0) == buf);

        assert_se(efi_memcpy(buf, "", 1) == buf);
        assert_se(memcmp(buf, "", 1) == 0);
        assert_se(efi_memcpy(buf, "1", 1) == buf);
        assert_se(memcmp(buf, "1", 1) == 0);
        assert_se(efi_memcpy(buf, "23", 3) == buf);
        assert_se(memcmp(buf, "23", 3) == 0);
        assert_se(efi_memcpy(buf, "45\0ab\0\0\0c", 9) == buf);
        assert_se(memcmp(buf, "45\0ab\0\0\0c", 9) == 0);
}

TEST(efi_memset) {
        char buf[10];

        assert_se(!efi_memset(NULL, '1', 0));
        assert_se(!efi_memset(NULL, '1', 1));
        assert_se(efi_memset(buf, '1', 0) == buf);

        assert_se(efi_memset(buf, '2', 1) == buf);
        assert_se(memcmp(buf, "2", 1) == 0);
        assert_se(efi_memset(buf, '4', 4) == buf);
        assert_se(memcmp(buf, "4444", 4) == 0);
        assert_se(efi_memset(buf, 'a', 10) == buf);
        assert_se(memcmp(buf, "aaaaaaaaaa", 10) == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
