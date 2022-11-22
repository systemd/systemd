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

TEST(xstrn8_to_16) {
        char16_t *s = NULL;

        assert_se(xstrn8_to_16(NULL, 1) == NULL);
        assert_se(xstrn8_to_16("a", 0) == NULL);

        assert_se(s = xstrn8_to_16("", 1));
        assert_se(streq16(s, u""));
        free(s);

        assert_se(s = xstrn8_to_16("1", 1));
        assert_se(streq16(s, u"1"));
        free(s);

        assert_se(s = xstr8_to_16("abcxyzABCXYZ09 .,-_#*!\"§$%&/()=?`~"));
        assert_se(streq16(s, u"abcxyzABCXYZ09 .,-_#*!\"§$%&/()=?`~"));
        free(s);

        assert_se(s = xstr8_to_16("ÿⱿ𝇉 😺"));
        assert_se(streq16(s, u"ÿⱿ "));
        free(s);

        assert_se(s = xstrn8_to_16("¶¶", 3));
        assert_se(streq16(s, u"¶"));
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
        TEST_FNMATCH_ONE("start*end", "startend", true);
        TEST_FNMATCH_ONE("start*end", "startendend", true);
        TEST_FNMATCH_ONE("start*end", "startenddne", false);
        TEST_FNMATCH_ONE("start*end", "startendstartend", true);
        TEST_FNMATCH_ONE("start*end", "starten", false);
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
        TEST_FNMATCH_ONE("debian-*-*-*.*", "debian-jessie-2018-06-17-kernel-image-5.10.0-16-amd64.efi", true);

        /* These would take forever with a backtracking implementation. */
        TEST_FNMATCH_ONE(
                        "a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p*q*r*s*t*u*v*w*x*y*z*",
                        "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyy",
                        false);
        TEST_FNMATCH_ONE(
                        "a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p*q*r*s*t*u*v*w*x*y*z*",
                        "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz!!!!",
                        true);
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
