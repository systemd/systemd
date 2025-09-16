/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "efi-string.h"
#include "fileio.h"
#include "tests.h"

TEST(strlen8) {
        ASSERT_EQ(strlen8(NULL), 0u);
        ASSERT_EQ(strlen8(""), 0u);
        ASSERT_EQ(strlen8("1"), 1u);
        ASSERT_EQ(strlen8("11"), 2u);
        ASSERT_EQ(strlen8("123456789"), 9u);
        ASSERT_EQ(strlen8("12\0004"), 2u);
}

TEST(strlen16) {
        ASSERT_EQ(strlen16(NULL), 0u);
        ASSERT_EQ(strlen16(u""), 0u);
        ASSERT_EQ(strlen16(u"1"), 1u);
        ASSERT_EQ(strlen16(u"11"), 2u);
        ASSERT_EQ(strlen16(u"123456789"), 9u);
        ASSERT_EQ(strlen16(u"12\0004"), 2u);
}

TEST(strnlen8) {
        ASSERT_EQ(strnlen8(NULL, 0), 0u);
        ASSERT_EQ(strnlen8(NULL, 10), 0u);
        ASSERT_EQ(strnlen8("", 10), 0u);
        ASSERT_EQ(strnlen8("1", 10), 1u);
        ASSERT_EQ(strnlen8("11", 1), 1u);
        ASSERT_EQ(strnlen8("123456789", 7), 7u);
        ASSERT_EQ(strnlen8("12\0004", 5), 2u);
}

TEST(strnlen16) {
        ASSERT_EQ(strnlen16(NULL, 0), 0u);
        ASSERT_EQ(strnlen16(NULL, 10), 0u);
        ASSERT_EQ(strnlen16(u"", 10), 0u);
        ASSERT_EQ(strnlen16(u"1", 10), 1u);
        ASSERT_EQ(strnlen16(u"11", 1), 1u);
        ASSERT_EQ(strnlen16(u"123456789", 7), 7u);
        ASSERT_EQ(strnlen16(u"12\0004", 5), 2u);
}

TEST(strsize8) {
        ASSERT_EQ(strsize8(NULL), 0u);
        ASSERT_EQ(strsize8(""), 1u);
        ASSERT_EQ(strsize8("1"), 2u);
        ASSERT_EQ(strsize8("11"), 3u);
        ASSERT_EQ(strsize8("123456789"), 10u);
        ASSERT_EQ(strsize8("12\0004"), 3u);
}

TEST(strsize16) {
        ASSERT_EQ(strsize16(NULL), 0u);
        ASSERT_EQ(strsize16(u""), 2u);
        ASSERT_EQ(strsize16(u"1"), 4u);
        ASSERT_EQ(strsize16(u"11"), 6u);
        ASSERT_EQ(strsize16(u"123456789"), 20u);
        ASSERT_EQ(strsize16(u"12\0004"), 6u);
}

TEST(strtolower8) {
        char s[] = "\0001234abcDEF!\0zZ";

        ASSERT_NULL(strtolower8(NULL));

        ASSERT_PTR_EQ(strtolower8(s), s);
        ASSERT_EQ(memcmp(s, "\0001234abcDEF!\0zZ", sizeof(s)), 0);

        s[0] = '#';
        ASSERT_PTR_EQ(strtolower8(s), s);
        ASSERT_EQ(memcmp(s, "#1234abcdef!\0zZ", sizeof(s)), 0);
}

TEST(strtolower16) {
        char16_t s[] = u"\0001234abcDEF!\0zZ";

        ASSERT_NULL(strtolower16(NULL));

        ASSERT_PTR_EQ(strtolower16(s), s);
        ASSERT_EQ(memcmp(s, u"\0001234abcDEF!\0zZ", sizeof(s)), 0);

        s[0] = '#';
        ASSERT_PTR_EQ(strtolower16(s), s);
        ASSERT_EQ(memcmp(s, u"#1234abcdef!\0zZ", sizeof(s)), 0);
}

TEST(strncmp8) {
        ASSERT_LT(strncmp8(NULL, "", 10), 0);
        ASSERT_GT(strncmp8("", NULL, 10), 0);
        ASSERT_EQ(strncmp8(NULL, NULL, 0), 0);
        ASSERT_EQ(strncmp8(NULL, NULL, 10), 0);
        ASSERT_EQ(strncmp8("", "", 10), 0);
        ASSERT_EQ(strncmp8("abc", "abc", 2), 0);
        ASSERT_EQ(strncmp8("aBc", "aBc", 3), 0);
        ASSERT_EQ(strncmp8("aBC", "aBC", 4), 0);
        ASSERT_EQ(strncmp8("", "a", 0), 0);
        ASSERT_EQ(strncmp8("b", "a", 0), 0);
        ASSERT_LT(strncmp8("", "a", 3), 0);
        ASSERT_EQ(strncmp8("=", "=", 1), 0);
        ASSERT_LT(strncmp8("A", "a", 1), 0);
        ASSERT_GT(strncmp8("a", "A", 2), 0);
        ASSERT_GT(strncmp8("a", "Aa", 2), 0);
        ASSERT_LT(strncmp8("12\00034", "12345", 4), 0);
        ASSERT_LT(strncmp8("12\00034", "12345", SIZE_MAX), 0);
        ASSERT_EQ(strncmp8("abc\0def", "abc", SIZE_MAX), 0);
        ASSERT_LT(strncmp8("abc\0def", "abcdef", SIZE_MAX), 0);

        ASSERT_EQ(strncmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MIN }, 1), 0);
        ASSERT_EQ(strncmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MAX }, 1), 0);
        ASSERT_LT(strncmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MAX }, 1), 0);
        ASSERT_GT(strncmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MIN }, 1), 0);
}

TEST(strncmp16) {
        ASSERT_LT(strncmp16(NULL, u"", 10), 0);
        ASSERT_GT(strncmp16(u"", NULL, 10), 0);
        ASSERT_EQ(strncmp16(NULL, NULL, 0), 0);
        ASSERT_EQ(strncmp16(NULL, NULL, 10), 0);
        ASSERT_EQ(strncmp16(u"", u"", 0), 0);
        ASSERT_EQ(strncmp16(u"", u"", 10), 0);
        ASSERT_EQ(strncmp16(u"abc", u"abc", 2), 0);
        ASSERT_EQ(strncmp16(u"aBc", u"aBc", 3), 0);
        ASSERT_EQ(strncmp16(u"aBC", u"aBC", 4), 0);
        ASSERT_EQ(strncmp16(u"", u"a", 0), 0);
        ASSERT_EQ(strncmp16(u"b", u"a", 0), 0);
        ASSERT_LT(strncmp16(u"", u"a", 3), 0);
        ASSERT_EQ(strncmp16(u"=", u"=", 1), 0);
        ASSERT_LT(strncmp16(u"A", u"a", 1), 0);
        ASSERT_GT(strncmp16(u"a", u"A", 2), 0);
        ASSERT_GT(strncmp16(u"a", u"Aa", 2), 0);
        ASSERT_LT(strncmp16(u"12\00034", u"12345", 4), 0);
        ASSERT_LT(strncmp16(u"12\00034", u"12345", SIZE_MAX), 0);
        ASSERT_EQ(strncmp16(u"abc\0def", u"abc", SIZE_MAX), 0);
        ASSERT_LT(strncmp16(u"abc\0def", u"abcdef", SIZE_MAX), 0);

        ASSERT_EQ(strncmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ UINT16_MAX }, 1), 0);
        ASSERT_LT(strncmp16((char16_t[]){ 0 }, (char16_t[]){ UINT16_MAX }, 1), 0);
        ASSERT_GT(strncmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ 0 }, 1), 0);
}

TEST(strncasecmp8) {
        ASSERT_LT(strncasecmp8(NULL, "", 10), 0);
        ASSERT_GT(strncasecmp8("", NULL, 10), 0);
        ASSERT_EQ(strncasecmp8(NULL, NULL, 0), 0);
        ASSERT_EQ(strncasecmp8(NULL, NULL, 10), 0);
        ASSERT_EQ(strncasecmp8("", "", 10), 0);
        ASSERT_EQ(strncasecmp8("abc", "abc", 2), 0);
        ASSERT_EQ(strncasecmp8("aBc", "AbC", 3), 0);
        ASSERT_EQ(strncasecmp8("aBC", "Abc", 4), 0);
        ASSERT_EQ(strncasecmp8("", "a", 0), 0);
        ASSERT_EQ(strncasecmp8("b", "a", 0), 0);
        ASSERT_LT(strncasecmp8("", "a", 3), 0);
        ASSERT_EQ(strncasecmp8("=", "=", 1), 0);
        ASSERT_EQ(strncasecmp8("A", "a", 1), 0);
        ASSERT_EQ(strncasecmp8("a", "A", 2), 0);
        ASSERT_LT(strncasecmp8("a", "Aa", 2), 0);
        ASSERT_LT(strncasecmp8("12\00034", "12345", 4), 0);
        ASSERT_LT(strncasecmp8("12\00034", "12345", SIZE_MAX), 0);
        ASSERT_EQ(strncasecmp8("abc\0def", "ABC", SIZE_MAX), 0);
        ASSERT_LT(strncasecmp8("abc\0def", "ABCDEF", SIZE_MAX), 0);

        ASSERT_EQ(strncasecmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MIN }, 1), 0);
        ASSERT_EQ(strncasecmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MAX }, 1), 0);
        ASSERT_LT(strncasecmp8((char[]){ CHAR_MIN }, (char[]){ CHAR_MAX }, 1), 0);
        ASSERT_GT(strncasecmp8((char[]){ CHAR_MAX }, (char[]){ CHAR_MIN }, 1), 0);
}

TEST(strncasecmp16) {
        ASSERT_LT(strncasecmp16(NULL, u"", 10), 0);
        ASSERT_GT(strncasecmp16(u"", NULL, 10), 0);
        ASSERT_EQ(strncasecmp16(NULL, NULL, 0), 0);
        ASSERT_EQ(strncasecmp16(NULL, NULL, 10), 0);
        ASSERT_EQ(strncasecmp16(u"", u"", 10), 0);
        ASSERT_EQ(strncasecmp16(u"abc", u"abc", 2), 0);
        ASSERT_EQ(strncasecmp16(u"aBc", u"AbC", 3), 0);
        ASSERT_EQ(strncasecmp16(u"aBC", u"Abc", 4), 0);
        ASSERT_EQ(strncasecmp16(u"", u"a", 0), 0);
        ASSERT_EQ(strncasecmp16(u"b", u"a", 0), 0);
        ASSERT_LT(strncasecmp16(u"", u"a", 3), 0);
        ASSERT_EQ(strncasecmp16(u"=", u"=", 1), 0);
        ASSERT_EQ(strncasecmp16(u"A", u"a", 1), 0);
        ASSERT_EQ(strncasecmp16(u"a", u"A", 2), 0);
        ASSERT_LT(strncasecmp16(u"a", u"Aa", 2), 0);
        ASSERT_LT(strncasecmp16(u"12\00034", u"12345", 4), 0);
        ASSERT_LT(strncasecmp16(u"12\00034", u"12345", SIZE_MAX), 0);
        ASSERT_EQ(strncasecmp16(u"abc\0def", u"ABC", SIZE_MAX), 0);
        ASSERT_LT(strncasecmp16(u"abc\0def", u"ABCDEF", SIZE_MAX), 0);

        ASSERT_EQ(strncasecmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ UINT16_MAX }, 1), 0);
        ASSERT_LT(strncasecmp16((char16_t[]){ 0 }, (char16_t[]){ UINT16_MAX }, 1), 0);
        ASSERT_GT(strncasecmp16((char16_t[]){ UINT16_MAX }, (char16_t[]){ 0 }, 1), 0);
}

TEST(strcpy8) {
        char buf[128];

        ASSERT_PTR_EQ(strcpy8(buf, "123"), buf);
        ASSERT_TRUE(streq8(buf, "123"));
        ASSERT_PTR_EQ(strcpy8(buf, ""), buf);
        ASSERT_TRUE(streq8(buf, ""));
        ASSERT_PTR_EQ(strcpy8(buf, "A"), buf);
        ASSERT_TRUE(streq8(buf, "A"));
        ASSERT_PTR_EQ(strcpy8(buf, NULL), buf);
        ASSERT_TRUE(streq8(buf, ""));
}

TEST(strcpy16) {
        char16_t buf[128];

        ASSERT_PTR_EQ(strcpy16(buf, u"123"), buf);
        ASSERT_TRUE(streq16(buf, u"123"));
        ASSERT_PTR_EQ(strcpy16(buf, u""), buf);
        ASSERT_TRUE(streq16(buf, u""));
        ASSERT_PTR_EQ(strcpy16(buf, u"A"), buf);
        ASSERT_TRUE(streq16(buf, u"A"));
        ASSERT_PTR_EQ(strcpy16(buf, NULL), buf);
        ASSERT_TRUE(streq16(buf, u""));
}

TEST(strchr8) {
        ASSERT_NULL(strchr8(NULL, 'a'));
        ASSERT_NULL(strchr8("", 'a'));
        ASSERT_NULL(strchr8("123", 'a'));

        const char str[] = "abcaBc";
        ASSERT_PTR_EQ(strchr8(str, 'a'), &str[0]);
        ASSERT_PTR_EQ(strchr8(str, 'c'), &str[2]);
        ASSERT_PTR_EQ(strchr8(str, 'B'), &str[4]);

        ASSERT_PTR_EQ(strchr8(str, 0), str + strlen8(str));
}

TEST(strchr16) {
        ASSERT_NULL(strchr16(NULL, 'a'));
        ASSERT_NULL(strchr16(u"", 'a'));
        ASSERT_NULL(strchr16(u"123", 'a'));

        const char16_t str[] = u"abcaBc";
        ASSERT_PTR_EQ(strchr16(str, 'a'), &str[0]);
        ASSERT_PTR_EQ(strchr16(str, 'c'), &str[2]);
        ASSERT_PTR_EQ(strchr16(str, 'B'), &str[4]);

        ASSERT_PTR_EQ(strchr16(str, 0), str + strlen16(str));
}

TEST(xstrndup8) {
        char *s = NULL;

        ASSERT_NULL(xstrndup8(NULL, 0));
        ASSERT_NULL(xstrndup8(NULL, 10));

        ASSERT_NOT_NULL(s = xstrndup8("", 10));
        ASSERT_TRUE(streq8(s, ""));
        free(s);

        ASSERT_NOT_NULL(s = xstrndup8("abc", 0));
        ASSERT_TRUE(streq8(s, ""));
        free(s);

        ASSERT_NOT_NULL(s = xstrndup8("ABC", 3));
        ASSERT_TRUE(streq8(s, "ABC"));
        free(s);

        ASSERT_NOT_NULL(s = xstrndup8("123abcDEF", 5));
        ASSERT_TRUE(streq8(s, "123ab"));
        free(s);
}

TEST(xstrdup8) {
        char *s = NULL;

        ASSERT_NULL(xstrdup8(NULL));

        ASSERT_NOT_NULL(s = xstrdup8(""));
        ASSERT_TRUE(streq8(s, ""));
        free(s);

        ASSERT_NOT_NULL(s = xstrdup8("1"));
        ASSERT_TRUE(streq8(s, "1"));
        free(s);

        ASSERT_NOT_NULL(s = xstrdup8("123abcDEF"));
        ASSERT_TRUE(streq8(s, "123abcDEF"));
        free(s);
}

TEST(xstrndup16) {
        char16_t *s = NULL;

        ASSERT_NULL(xstrndup16(NULL, 0));
        ASSERT_NULL(xstrndup16(NULL, 10));

        ASSERT_NOT_NULL(s = xstrndup16(u"", 10));
        ASSERT_TRUE(streq16(s, u""));
        free(s);

        ASSERT_NOT_NULL(s = xstrndup16(u"abc", 0));
        ASSERT_TRUE(streq16(s, u""));
        free(s);

        ASSERT_NOT_NULL(s = xstrndup16(u"ABC", 3));
        ASSERT_TRUE(streq16(s, u"ABC"));
        free(s);

        ASSERT_NOT_NULL(s = xstrndup16(u"123abcDEF", 5));
        ASSERT_TRUE(streq16(s, u"123ab"));
        free(s);
}

TEST(xstrdup16) {
        char16_t *s = NULL;

        ASSERT_NULL(xstrdup16(NULL));

        ASSERT_NOT_NULL(s = xstrdup16(u""));
        ASSERT_TRUE(streq16(s, u""));
        free(s);

        ASSERT_NOT_NULL(s = xstrdup16(u"1"));
        ASSERT_TRUE(streq16(s, u"1"));
        free(s);

        ASSERT_NOT_NULL(s = xstrdup16(u"123abcDEF"));
        ASSERT_TRUE(streq16(s, u"123abcDEF"));
        free(s);
}

TEST(xstrn8_to_16) {
        char16_t *s = NULL;

        ASSERT_NOT_NULL(s = xstrn8_to_16(NULL, 0));
        ASSERT_TRUE(streq16(s, u""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn8_to_16("", 0));
        ASSERT_TRUE(streq16(s, u""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn8_to_16("a", 0));
        ASSERT_TRUE(streq16(s, u""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn8_to_16("", 1));
        ASSERT_TRUE(streq16(s, u""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn8_to_16("1", 1));
        ASSERT_TRUE(streq16(s, u"1"));
        free(s);

        ASSERT_NOT_NULL(s = xstr8_to_16("abcxyzABCXYZ09 .,-_#*!\"§$%&/()=?`~"));
        ASSERT_TRUE(streq16(s, u"abcxyzABCXYZ09 .,-_#*!\"§$%&/()=?`~"));
        free(s);

        ASSERT_NOT_NULL(s = xstr8_to_16("ÿⱿ𝇉 😺"));
        ASSERT_TRUE(streq16(s, u"ÿⱿ "));
        free(s);

        ASSERT_NOT_NULL(s = xstrn8_to_16("¶¶", 3));
        ASSERT_TRUE(streq16(s, u"¶"));
        free(s);
}

TEST(xstrn16_to_ascii) {
        char *s;

        ASSERT_NOT_NULL(s = xstrn16_to_ascii(NULL, 0));
        ASSERT_TRUE(streq8(s, ""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn16_to_ascii(u"", 0));
        ASSERT_TRUE(streq8(s, ""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn16_to_ascii(u"a", 0));
        ASSERT_TRUE(streq8(s, ""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn16_to_ascii(u"", 1));
        ASSERT_TRUE(streq8(s, ""));
        free(s);

        ASSERT_NOT_NULL(s = xstrn16_to_ascii(u"1", 1));
        ASSERT_TRUE(streq8(s, "1"));
        free(s);

        ASSERT_NOT_NULL(s = xstr16_to_ascii(u"abcxyzABCXYZ09 .,-_#*!\"$%&/()=?`~"));
        ASSERT_TRUE(streq8(s, "abcxyzABCXYZ09 .,-_#*!\"$%&/()=?`~"));
        free(s);

        ASSERT_NULL(xstr16_to_ascii(u"ÿⱿ𝇉 😺"));
        ASSERT_NULL(xstr16_to_ascii(u"¶¶"));
}

TEST(startswith8) {
        ASSERT_TRUE(streq8(startswith8("", ""), ""));
        ASSERT_TRUE(streq8(startswith8("x", ""), "x"));
        ASSERT_NULL(startswith8("", "x"));
        ASSERT_NULL(startswith8("", "xxxxxxxx"));
        ASSERT_TRUE(streq8(startswith8("xxx", "x"), "xx"));
        ASSERT_TRUE(streq8(startswith8("xxx", "xx"), "x"));
        ASSERT_TRUE(streq8(startswith8("xxx", "xxx"), ""));
        ASSERT_NULL(startswith8("xxx", "xxxx"));
        ASSERT_NULL(startswith8(NULL, ""));
}

#define TEST_FNMATCH_ONE_FULL(pattern, haystack, expect, skip_libc)     \
        ({                                                              \
                if (!skip_libc)                                         \
                        ASSERT_EQ(fnmatch(pattern, haystack, 0), expect ? 0 : FNM_NOMATCH); \
                ASSERT_EQ(efi_fnmatch(u##pattern, u##haystack), expect); \
        })

#define TEST_FNMATCH_ONE(pattern, haystack, expect)             \
        TEST_FNMATCH_ONE_FULL(pattern, haystack, expect, false)

TEST(efi_fnmatch) {
        bool skip_libc;

#ifdef __GLIBC__
        skip_libc = false;
#else
        /* It seems musl is too strict in handling "[]" (or has a bug?). Anyway, let's skip some test cases
         * when built with musl. The behavior of efi_fnmatch() does not need to match musl's fnmatch(). */
        skip_libc = true;
#endif

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
        TEST_FNMATCH_ONE_FULL("[1\\]] [1\\]]", "1 ]", true, skip_libc);
        TEST_FNMATCH_ONE("[$-\\+]", "&", true);
        TEST_FNMATCH_ONE("[1-3A-C] [1-3A-C]", "2 B", true);
        TEST_FNMATCH_ONE("[3-5] [3-5] [3-5]", "3 4 5", true);
        TEST_FNMATCH_ONE("[f-h] [f-h] [f-h]", "f g h", true);
        TEST_FNMATCH_ONE_FULL("[a-c-f] [a-c-f] [a-c-f] [a-c-f] [a-c-f]", "a b c - f", true, skip_libc);
        TEST_FNMATCH_ONE_FULL("[a-c-f]", "e", false, skip_libc);
        TEST_FNMATCH_ONE("[--0] [--0] [--0]", "- . 0", true);
        TEST_FNMATCH_ONE("[+--] [+--] [+--]", "+ , -", true);
        TEST_FNMATCH_ONE("[f-l]", "m", false);
        TEST_FNMATCH_ONE("[b]", "z-a", false);
        TEST_FNMATCH_ONE_FULL("[a\\-z]", "b", false, skip_libc);
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

        ASSERT_FALSE(parse_number8(NULL, &u, NULL));
        ASSERT_FALSE(parse_number8("", &u, NULL));
        ASSERT_FALSE(parse_number8("a1", &u, NULL));
        ASSERT_FALSE(parse_number8("1a", &u, NULL));
        ASSERT_FALSE(parse_number8("-42", &u, NULL));
        ASSERT_FALSE(parse_number8("18446744073709551616", &u, NULL));

        ASSERT_TRUE(parse_number8("0", &u, NULL));
        ASSERT_EQ(u, 0u);
        ASSERT_TRUE(parse_number8("1", &u, NULL));
        ASSERT_EQ(u, 1u);
        ASSERT_TRUE(parse_number8("999", &u, NULL));
        ASSERT_EQ(u, 999u);
        ASSERT_TRUE(parse_number8("18446744073709551615", &u, NULL));
        ASSERT_EQ(u, UINT64_MAX);
        ASSERT_TRUE(parse_number8("42", &u, &tail));
        ASSERT_EQ(u, 42u);
        ASSERT_TRUE(streq8(tail, ""));
        ASSERT_TRUE(parse_number8("54321rest", &u, &tail));
        ASSERT_EQ(u, 54321u);
        ASSERT_TRUE(streq8(tail, "rest"));
}

TEST(parse_number16) {
        uint64_t u;
        const char16_t *tail;

        ASSERT_FALSE(parse_number16(NULL, &u, NULL));
        ASSERT_FALSE(parse_number16(u"", &u, NULL));
        ASSERT_FALSE(parse_number16(u"a1", &u, NULL));
        ASSERT_FALSE(parse_number16(u"1a", &u, NULL));
        ASSERT_FALSE(parse_number16(u"-42", &u, NULL));
        ASSERT_FALSE(parse_number16(u"18446744073709551616", &u, NULL));

        ASSERT_TRUE(parse_number16(u"0", &u, NULL));
        ASSERT_EQ(u, 0u);
        ASSERT_TRUE(parse_number16(u"1", &u, NULL));
        ASSERT_EQ(u, 1u);
        ASSERT_TRUE(parse_number16(u"999", &u, NULL));
        ASSERT_EQ(u, 999u);
        ASSERT_TRUE(parse_number16(u"18446744073709551615", &u, NULL));
        ASSERT_EQ(u, UINT64_MAX);
        ASSERT_TRUE(parse_number16(u"42", &u, &tail));
        ASSERT_EQ(u, 42u);
        ASSERT_TRUE(streq16(tail, u""));
        ASSERT_TRUE(parse_number16(u"54321rest", &u, &tail));
        ASSERT_EQ(u, 54321u);
        ASSERT_TRUE(streq16(tail, u"rest"));
}

TEST(parse_boolean) {
        bool b;

        ASSERT_FALSE(parse_boolean(NULL, &b));
        ASSERT_FALSE(parse_boolean("", &b));
        ASSERT_FALSE(parse_boolean("ja", &b));
        ASSERT_TRUE(parse_boolean("1", &b));
        ASSERT_TRUE(b);
        ASSERT_TRUE(parse_boolean("y", &b));
        ASSERT_TRUE(b);
        ASSERT_TRUE(parse_boolean("yes", &b));
        ASSERT_TRUE(b);
        ASSERT_TRUE(parse_boolean("t", &b));
        ASSERT_TRUE(b);
        ASSERT_TRUE(parse_boolean("true", &b));
        ASSERT_TRUE(b);
        ASSERT_TRUE(parse_boolean("on", &b));
        ASSERT_TRUE(b);
        ASSERT_TRUE(parse_boolean("0", &b));
        ASSERT_FALSE(b);
        ASSERT_TRUE(parse_boolean("n", &b));
        ASSERT_FALSE(b);
        ASSERT_TRUE(parse_boolean("no", &b));
        ASSERT_FALSE(b);
        ASSERT_TRUE(parse_boolean("f", &b));
        ASSERT_FALSE(b);
        ASSERT_TRUE(parse_boolean("false", &b));
        ASSERT_FALSE(b);
        ASSERT_TRUE(parse_boolean("off", &b));
        ASSERT_FALSE(b);
}

TEST(line_get_key_value) {
        char s1[] = "key=value\n"
                    " \t  # comment line \n"
                    "k-e-y=\"quoted value\"\n\r"
                    "  wrong= 'quotes' \n"
                    "odd= stripping  # with comments  ";
        char s2[] = "this parser\n"
                    "\t\t\t# is\t\r"
                    "  also\tused  \r\n"
                    "for \"the conf\"\n"
                    "format\t !!";
        size_t pos = 0;
        char *key, *value;

        ASSERT_NULL(line_get_key_value((char[]){ "" }, "=", &pos, &key, &value));
        ASSERT_NULL(line_get_key_value((char[]){ "\t" }, " \t", &pos, &key, &value));

        pos = 0;
        ASSERT_NOT_NULL(line_get_key_value(s1, "=", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "key"));
        ASSERT_TRUE(streq8(value, "value"));
        ASSERT_NOT_NULL(line_get_key_value(s1, "=", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "k-e-y"));
        ASSERT_TRUE(streq8(value, "quoted value"));
        ASSERT_NOT_NULL(line_get_key_value(s1, "=", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "wrong"));
        ASSERT_TRUE(streq8(value, " 'quotes'"));
        ASSERT_NOT_NULL(line_get_key_value(s1, "=", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "odd"));
        ASSERT_TRUE(streq8(value, " stripping  # with comments"));
        ASSERT_NULL(line_get_key_value(s1, "=", &pos, &key, &value));

        pos = 0;
        ASSERT_NOT_NULL(line_get_key_value(s2, " \t", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "this"));
        ASSERT_TRUE(streq8(value, "parser"));
        ASSERT_NOT_NULL(line_get_key_value(s2, " \t", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "also"));
        ASSERT_TRUE(streq8(value, "used"));
        ASSERT_NOT_NULL(line_get_key_value(s2, " \t", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "for"));
        ASSERT_TRUE(streq8(value, "the conf"));
        ASSERT_NOT_NULL(line_get_key_value(s2, " \t", &pos, &key, &value));
        ASSERT_TRUE(streq8(key, "format"));
        ASSERT_TRUE(streq8(value, "!!"));
        ASSERT_NULL(line_get_key_value(s2, " \t", &pos, &key, &value));

        /* Let's make sure we don't fail on real os-release data. */
        _cleanup_free_ char *osrel = NULL;
        if (read_full_file("/usr/lib/os-release", &osrel, NULL) >= 0) {
                pos = 0;
                while (line_get_key_value(osrel, "=", &pos, &key, &value)) {
                        ASSERT_NOT_NULL(key);
                        ASSERT_NOT_NULL(value);
                        printf("%s = %s\n", key, value);
                }
        }
}

TEST(hexdump) {
        char16_t *hex;

        ASSERT_NOT_NULL(hex = hexdump(NULL, 0));
        ASSERT_TRUE(streq16(hex, u""));
        free(hex);

        ASSERT_NOT_NULL(hex = hexdump("1", 2));
        ASSERT_TRUE(streq16(hex, u"3100"));
        free(hex);

        ASSERT_NOT_NULL(hex = hexdump("abc", 4));
        ASSERT_TRUE(streq16(hex, u"61626300"));
        free(hex);

        ASSERT_NOT_NULL(hex = hexdump((uint8_t[]){ 0x0, 0x42, 0xFF, 0xF1, 0x1F }, 5));
        ASSERT_TRUE(streq16(hex, u"0042fff11f"));
        free(hex);
}

_printf_(1, 2) static void test_printf_one(const char *format, ...) {
        va_list ap, ap_efi;
        int r;

        va_start(ap, format);
        va_copy(ap_efi, ap);

        _cleanup_free_ char *buf = NULL;
        ASSERT_OK(r = vasprintf(&buf, format, ap));
        log_info("/* %s(%s) -> \"%.100s\" */", __func__, format, buf);

        _cleanup_free_ char16_t *buf_efi = NULL;
        ASSERT_NOT_NULL(buf_efi = xvasprintf_status(0, format, ap_efi));

        bool eq = true;
        for (size_t i = 0; i <= (size_t) r; i++) {
                if (buf[i] != buf_efi[i])
                        eq = false;
                buf[i] = buf_efi[i];
        }

        log_info("%.100s", buf);
        ASSERT_TRUE(eq);

        va_end(ap);
        va_end(ap_efi);
}

TEST(xvasprintf_status) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"
        test_printf_one("");
#pragma GCC diagnostic pop
        test_printf_one("string");
        test_printf_one("%%-%%%%");

#ifdef __GLIBC__
        test_printf_one("%p %p %32p %*p %*p", NULL, (void *) 0xF, &errno, 0, &saved_argc, 20, &saved_argv);
        test_printf_one("%-10p %-32p %-*p %-*p", NULL, &errno, 0, &saved_argc, 20, &saved_argv);
#else
        /* musl prints NULL as 0, while glibc and our implementation print it as (nil). */
        test_printf_one("%p %32p %*p %*p", (void *) 0xF, &errno, 0, &saved_argc, 20, &saved_argv);
        test_printf_one("%-32p %-*p %-*p", &errno, 0, &saved_argc, 20, &saved_argv);
#endif

        test_printf_one("%c %3c %*c %*c %-8c", '1', '!', 0, 'a', 9, '_', '>');

        test_printf_one("%s %s %s", "012345", "6789", "ab");
        test_printf_one("%.4s %.4s %.4s %.0s", "cdefgh", "ijkl", "mn", "@");
        test_printf_one("%8s %8s %8s", "opqrst", "uvwx", "yz");
        test_printf_one("%8.4s %8.4s %8.4s %8.0s", "ABCDEF", "GHIJ", "KL", "$");
        test_printf_one("%4.8s %4.8s %4.8s", "ABCDEFGHIJ", "ABCDEFGH", "ABCD");

        test_printf_one("%.*s %.*s %.*s %.*s", 4, "012345", 4, "6789", 4, "ab", 0, "&");
        test_printf_one("%*s %*s %*s", 8, "cdefgh", 8, "ijkl", 8, "mn");
        test_printf_one("%*.*s %*.*s %*.*s %*.*s", 8, 4, "opqrst", 8, 4, "uvwx", 8, 4, "yz", 8, 0, "#");
        test_printf_one("%*.*s %*.*s %*.*s", 3, 8, "OPQRST", 3, 8, "UVWX", 3, 8, "YZ");

        test_printf_one("%ls %ls %ls", L"012345", L"6789", L"ab");
        test_printf_one("%.4ls %.4ls %.4ls %.0ls", L"cdefgh", L"ijkl", L"mn", L"@");
        test_printf_one("%8ls %8ls %8ls", L"opqrst", L"uvwx", L"yz");
        test_printf_one("%8.4ls %8.4ls %8.4ls %8.0ls", L"ABCDEF", L"GHIJ", L"KL", L"$");
        test_printf_one("%4.8ls %4.8ls %4.8ls", L"ABCDEFGHIJ", L"ABCDEFGH", L"ABCD");

        test_printf_one("%.*ls %.*ls %.*ls %.*ls", 4, L"012345", 4, L"6789", 4, L"ab", 0, L"&");
        test_printf_one("%*ls %*ls %*ls", 8, L"cdefgh", 8, L"ijkl", 8, L"mn");
        test_printf_one("%*.*ls %*.*ls %*.*ls %*.*ls", 8, 4, L"opqrst", 8, 4, L"uvwx", 8, 4, L"yz", 8, 0, L"#");
        test_printf_one("%*.*ls %*.*ls %*.*ls", 3, 8, L"OPQRST", 3, 8, L"UVWX", 3, 8, L"YZ");

        test_printf_one("%-14s %-10.0s %-10.3s", "left", "", "chopped");
        test_printf_one("%-14ls %-10.0ls %-10.3ls", L"left", L"", L"chopped");

        test_printf_one("%.6s", (char[]){ 'n', 'o', ' ', 'n', 'u', 'l' });
        test_printf_one("%.6ls", (wchar_t[]){ 'n', 'o', ' ', 'n', 'u', 'l' });

        test_printf_one("%u %u %u", 0U, 42U, 1234567890U);
        test_printf_one("%i %i %i", 0, -42, -1234567890);
        test_printf_one("%x %x %x", 0x0U, 0x42U, 0x123ABCU);
        test_printf_one("%X %X %X", 0x1U, 0x43U, 0x234BCDU);
        test_printf_one("%#x %#x %#x", 0x2U, 0x44U, 0x345CDEU);
        test_printf_one("%#X %#X %#X", 0x3U, 0x45U, 0x456FEDU);

        test_printf_one("%u %lu %llu %zu", UINT_MAX, ULONG_MAX, ULLONG_MAX, SIZE_MAX);
        test_printf_one("%i %i %zi", INT_MIN, INT_MAX, SSIZE_MAX);
        test_printf_one("%li %li %lli %lli", LONG_MIN, LONG_MAX, LLONG_MIN, LLONG_MAX);
        test_printf_one("%x %#lx %llx %#zx", UINT_MAX, ULONG_MAX, ULLONG_MAX, SIZE_MAX);
        test_printf_one("%X %#lX %llX %#zX", UINT_MAX, ULONG_MAX, ULLONG_MAX, SIZE_MAX);
        test_printf_one("%ju %ji %ji", UINTMAX_MAX, INTMAX_MIN, INTMAX_MAX);
        test_printf_one("%ti %ti", PTRDIFF_MIN, PTRDIFF_MAX);

        test_printf_one("%" PRIu32 " %" PRIi32 " %" PRIi32, UINT32_MAX, INT32_MIN, INT32_MAX);
        test_printf_one("%" PRIx32 " %" PRIX32, UINT32_MAX, UINT32_MAX);
        test_printf_one("%#" PRIx32 " %#" PRIX32, UINT32_MAX, UINT32_MAX);

        test_printf_one("%" PRIu64 " %" PRIi64 " %" PRIi64, UINT64_MAX, INT64_MIN, INT64_MAX);
        test_printf_one("%" PRIx64 " %" PRIX64, UINT64_MAX, UINT64_MAX);
        test_printf_one("%#" PRIx64 " %#" PRIX64, UINT64_MAX, UINT64_MAX);

        test_printf_one("%.11u %.11i %.11x %.11X %#.11x %#.11X", 1U, -2, 3U, 0xA1U, 0xB2U, 0xC3U);
        test_printf_one("%13u %13i %13x %13X %#13x %#13X", 4U, -5, 6U, 0xD4U, 0xE5U, 0xF6U);
        test_printf_one("%9.5u %9.5i %9.5x %9.5X %#9.5x %#9.5X", 7U, -8, 9U, 0xA9U, 0xB8U, 0xC7U);
        test_printf_one("%09u %09i %09x %09X %#09x %#09X", 4U, -5, 6U, 0xD6U, 0xE5U, 0xF4U);

        test_printf_one("%*u %.*u %*i %.*i", 15, 42U, 15, 43U, 15, -42, 15, -43);
        test_printf_one("%*.*u %*.*i", 14, 10, 13U, 14, 10, -14);
        test_printf_one("%*x %*X %.*x %.*X", 15, 0x1AU, 15, 0x2BU, 15, 0x3CU, 15, 0x4DU);
        test_printf_one("%#*x %#*X %#.*x %#.*X", 15, 0xA1U, 15, 0xB2U, 15, 0xC3U, 15, 0xD4U);
        test_printf_one("%*.*x %*.*X", 14, 10, 0x1AU, 14, 10, 0x2BU);
        test_printf_one("%#*.*x %#*.*X", 14, 10, 0x3CU, 14, 10, 0x4DU);

        test_printf_one("%+.5i %+.5i % .7i % .7i", -15, 51, -15, 51);
        test_printf_one("%+5.i %+5.i % 7.i % 7.i", -15, 51, -15, 51);

        test_printf_one("%-10u %-10i %-10x %#-10X %- 10i", 1u, -2, 0xA2D2u, 0XB3F4u, -512);
        test_printf_one("%-10.6u %-10.6i %-10.6x %#-10.6X %- 10.6i", 1u, -2, 0xA2D2u, 0XB3F4u, -512);
        test_printf_one("%-6.10u %-6.10i %-6.10x %#-6.10X %- 6.10i", 3u, -4, 0x2A2Du, 0X3B4Fu, -215);
        test_printf_one("%*.u %.*i %.*i", -4, 9u, -4, 8, -4, -6);

        test_printf_one("%.0u %.0i %.0x %.0X", 0u, 0, 0u, 0u);
        test_printf_one("%.*u %.*i %.*x %.*X", 0, 0u, 0, 0, 0, 0u, 0, 0u);
        test_printf_one("%*u %*i %*x %*X", -1, 0u, -1, 0, -1, 0u, -1, 0u);

        test_printf_one("%*s%*s%*s", 256, "", 256, "", 4096, ""); /* Test buf growing. */
        test_printf_one("%0*i%0*i%0*i", 256, 0, 256, 0, 4096, 0); /* Test buf growing. */
        test_printf_one("%0*i", INT16_MAX, 0); /* Poor programmer's memzero. */

        /* Non printf-compatible behavior tests below. */
        char16_t *s;

        ASSERT_NOT_NULL(s = xasprintf_status(0, "\n \r \r\n"));
        ASSERT_TRUE(streq16(s, u"\r\n \r \r\r\n"));
        s = mfree(s);

        ASSERT_NOT_NULL(s = xasprintf_status(EFI_SUCCESS, "%m"));
        ASSERT_TRUE(streq16(s, u"Success"));
        s = mfree(s);

        ASSERT_NOT_NULL(s = xasprintf_status(EFI_SUCCESS, "%15m"));
        ASSERT_TRUE(streq16(s, u"        Success"));
        s = mfree(s);

        ASSERT_NOT_NULL(s = xasprintf_status(EFI_LOAD_ERROR, "%m"));
        ASSERT_TRUE(streq16(s, u"Load error"));
        s = mfree(s);

        ASSERT_NOT_NULL(s = xasprintf_status(0x42, "%m"));
        ASSERT_TRUE(streq16(s, u"0x42"));
        s = mfree(s);
}

TEST(efi_memchr) {
        ASSERT_TRUE(streq8(efi_memchr("abcde", 'c', 5), "cde"));
        ASSERT_TRUE(streq8(efi_memchr("abcde", 'c', 3), "cde"));
        ASSERT_TRUE(streq8(efi_memchr("abcde", 'c', 2), NULL));
        ASSERT_TRUE(streq8(efi_memchr("abcde", 'c', 7), "cde"));
        ASSERT_TRUE(streq8(efi_memchr("abcde", 'q', 5), NULL));
        ASSERT_TRUE(streq8(efi_memchr("abcde", 'q', 0), NULL));
        /* Test that the character is interpreted as unsigned char. */
        ASSERT_TRUE(streq8(efi_memchr("abcde", 'a', 6), efi_memchr("abcde", 'a' + 0x100, 6)));
        ASSERT_TRUE(streq8(efi_memchr("abcde", 0, 6), ""));
        ASSERT_NULL(efi_memchr(NULL, 0, 0));
}

TEST(efi_memcmp) {
        ASSERT_EQ(efi_memcmp(NULL, NULL, 0), 0);
        ASSERT_EQ(efi_memcmp(NULL, NULL, 1), 0);
        ASSERT_LT(efi_memcmp(NULL, "", 1), 0);
        ASSERT_GT(efi_memcmp("", NULL, 1), 0);
        ASSERT_EQ(efi_memcmp("", "", 0), 0);
        ASSERT_EQ(efi_memcmp("", "", 1), 0);
        ASSERT_EQ(efi_memcmp("1", "1", 1), 0);
        ASSERT_LT(efi_memcmp("1", "2", 1), 0);
        ASSERT_LT(efi_memcmp("A", "a", 1), 0);
        ASSERT_GT(efi_memcmp("a", "A", 1), 0);
        ASSERT_EQ(efi_memcmp("abc", "ab", 2), 0);
        ASSERT_LT(efi_memcmp("ab", "abc", 3), 0);
        ASSERT_GT(efi_memcmp("abc", "ab", 3), 0);
        ASSERT_EQ(efi_memcmp("ab\000bd", "ab\000bd", 6), 0);
        ASSERT_LT(efi_memcmp("ab\000b\0", "ab\000bd", 6), 0);
}

TEST(efi_memcpy) {
        char buf[10];

        ASSERT_NULL(efi_memcpy(NULL, NULL, 0));
        ASSERT_NULL(efi_memcpy(NULL, "", 1));
        ASSERT_PTR_EQ(efi_memcpy(buf, NULL, 0), buf);
        ASSERT_PTR_EQ(efi_memcpy(buf, NULL, 1), buf);
        ASSERT_PTR_EQ(efi_memcpy(buf, "a", 0), buf);

        ASSERT_PTR_EQ(efi_memcpy(buf, "", 1), buf);
        ASSERT_EQ(memcmp(buf, "", 1), 0);
        ASSERT_PTR_EQ(efi_memcpy(buf, "1", 1), buf);
        ASSERT_EQ(memcmp(buf, "1", 1), 0);
        ASSERT_PTR_EQ(efi_memcpy(buf, "23", 3), buf);
        ASSERT_EQ(memcmp(buf, "23", 3), 0);
        ASSERT_PTR_EQ(efi_memcpy(buf, "45\0ab\0\0\0c", 9), buf);
        ASSERT_EQ(memcmp(buf, "45\0ab\0\0\0c", 9), 0);
}

TEST(efi_memset) {
        char buf[10];

        ASSERT_NULL(efi_memset(NULL, '1', 0));
        ASSERT_NULL(efi_memset(NULL, '1', 1));
        ASSERT_PTR_EQ(efi_memset(buf, '1', 0), buf);

        ASSERT_PTR_EQ(efi_memset(buf, '2', 1), buf);
        ASSERT_EQ(memcmp(buf, "2", 1), 0);
        ASSERT_PTR_EQ(efi_memset(buf, '4', 4), buf);
        ASSERT_EQ(memcmp(buf, "4444", 4), 0);
        ASSERT_PTR_EQ(efi_memset(buf, 'a', 10), buf);
        ASSERT_EQ(memcmp(buf, "aaaaaaaaaa", 10), 0);
}

TEST(efi_strspn) {
        ASSERT_EQ(strspn16(u"foobar", u"fo"), 3U);
        ASSERT_EQ(strspn16(u"foobar", u"ob"), 0U);
        ASSERT_EQ(strspn16(u"foobar", u"fxayzy"), 1U);
        ASSERT_EQ(strspn16(u"", u"abcdefef"), 0U);
        ASSERT_EQ(strspn16(u"", u""), 0U);
        ASSERT_EQ(strspn16(u"foobar", u""), 0U);
        ASSERT_EQ(strspn16(u"foffffffffffoobar", u"fofo"), 14U);
}

TEST(efi_strcspn) {
        ASSERT_EQ(strcspn16(u"foobar", u"fo"), 0U);
        ASSERT_EQ(strcspn16(u"foobar", u"bar"), 3U);
        ASSERT_EQ(strcspn16(u"foobar", u"xhyfzy"), 0U);
        ASSERT_EQ(strcspn16(u"foobar", u"xhyozy"), 1U);
        ASSERT_EQ(strcspn16(u"foobar", u"xhyzy"), 6U);
        ASSERT_EQ(strcspn16(u"", u"abcdefef"), 0U);
        ASSERT_EQ(strcspn16(u"", u""), 0U);
        ASSERT_EQ(strcspn16(u"foobar", u""), 6U);
        ASSERT_EQ(strcspn16(u"foffffffffffoobar", u"fofo"), 0U);
        ASSERT_EQ(strcspn16(u"foffffffffffoobar", u"a"), 15U);
}

DEFINE_TEST_MAIN(LOG_INFO);
