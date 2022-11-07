/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "nulstr-util.h"
#include "set.h"
#include "strv.h"
#include "tests.h"

TEST(strv_split_nulstr) {
        _cleanup_strv_free_ char **l = NULL;
        const char nulstr[] = "str0\0str1\0str2\0str3\0";

        l = strv_split_nulstr(nulstr);
        assert_se(l);

        assert_se(streq(l[0], "str0"));
        assert_se(streq(l[1], "str1"));
        assert_se(streq(l[2], "str2"));
        assert_se(streq(l[3], "str3"));
}

TEST(strv_parse_nulstr) {
        _cleanup_strv_free_ char **l = NULL;
        const char nulstr[] = "hoge\0hoge2\0hoge3\0\0hoge5\0\0xxx";

        l = strv_parse_nulstr(nulstr, sizeof(nulstr)-1);
        assert_se(l);
        puts("Parse nulstr:");
        strv_print(l);

        assert_se(streq(l[0], "hoge"));
        assert_se(streq(l[1], "hoge2"));
        assert_se(streq(l[2], "hoge3"));
        assert_se(streq(l[3], ""));
        assert_se(streq(l[4], "hoge5"));
        assert_se(streq(l[5], ""));
        assert_se(streq(l[6], "xxx"));
        strv_free(l);

        l = strv_parse_nulstr((const char[0]) {}, 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        strv_free(l);

        l = strv_parse_nulstr((const char[1]) { 0 }, 1);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("")));
        strv_free(l);

        l = strv_parse_nulstr((const char[1]) { 'x' }, 1);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("x")));
        strv_free(l);

        l = strv_parse_nulstr((const char[2]) { 0, 0 }, 2);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("", "")));
        strv_free(l);

        l = strv_parse_nulstr((const char[2]) { 'x', 0 }, 2);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("x")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 0, 0, 0 }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("", "", "")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 'x', 0, 0 }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("x", "")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 0, 'x', 0 }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("", "x")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 0, 0, 'x' }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("", "", "x")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 'x', 'x', 0 }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("xx")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 0, 'x', 'x' }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("", "xx")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 'x', 0, 'x' }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("x", "x")));
        strv_free(l);

        l = strv_parse_nulstr((const char[3]) { 'x', 'x', 'x' }, 3);
        assert_se(l);
        assert_se(strv_equal(l, STRV_MAKE("xxx")));
}

static void test_strv_make_nulstr_one(char **l) {
        _cleanup_free_ char *b = NULL, *c = NULL;
        _cleanup_strv_free_ char **q = NULL;
        size_t n, m;
        unsigned i = 0;

        log_info("/* %s */", __func__);

        assert_se(strv_make_nulstr(l, &b, &n) >= 0);
        assert_se(q = strv_parse_nulstr(b, n));
        assert_se(strv_equal(l, q));

        assert_se(strv_make_nulstr(q, &c, &m) >= 0);
        assert_se(memcmp_nn(b, n, c, m) == 0);

        NULSTR_FOREACH(s, b)
                assert_se(streq(s, l[i++]));
        assert_se(i == strv_length(l));
}

TEST(strv_make_nulstr) {
        test_strv_make_nulstr_one(NULL);
        test_strv_make_nulstr_one(STRV_MAKE(NULL));
        test_strv_make_nulstr_one(STRV_MAKE("foo"));
        test_strv_make_nulstr_one(STRV_MAKE("foo", "bar"));
        test_strv_make_nulstr_one(STRV_MAKE("foo", "bar", "quuux"));
}

TEST(set_make_nulstr) {
        _cleanup_set_free_free_ Set *set = NULL;
        size_t len = 0;
        int r;

        {
                /* Unallocated and empty set. */
                char expect[] = { 0x00, 0x00 };
                _cleanup_free_ char *nulstr = NULL;

                r = set_make_nulstr(set, &nulstr, &len);
                assert_se(r == 0);
                assert_se(len == 0);
                assert_se(memcmp(expect, nulstr, len + 2) == 0);
        }

        {
                /* Allocated by empty set. */
                char expect[] = { 0x00, 0x00 };
                _cleanup_free_ char *nulstr = NULL;

                set = set_new(NULL);
                assert_se(set);

                r = set_make_nulstr(set, &nulstr, &len);
                assert_se(r == 0);
                assert_se(len == 0);
                assert_se(memcmp(expect, nulstr, len + 2) == 0);
        }

        {
                /* Non-empty set. */
                char expect[] = { 'a', 'a', 'a', 0x00, 0x00 };
                _cleanup_free_ char *nulstr = NULL;

                assert_se(set_put_strdup(&set, "aaa") >= 0);

                r = set_make_nulstr(set, &nulstr, &len);
                assert_se(r == 0);
                assert_se(len == 4);
                assert_se(memcmp(expect, nulstr, len + 1) == 0);
        }
}

static void test_strv_make_nulstr_binary_one(char **l, const char *b, size_t n) {
        _cleanup_strv_free_ char **z = NULL;
        _cleanup_free_ char *a = NULL;
        size_t m;

        assert_se(strv_make_nulstr(l, &a, &m) >= 0);
        assert_se(memcmp_nn(a, m, b, n) == 0);
        assert_se(z = strv_parse_nulstr(a, m));
        assert_se(strv_equal(l, z));
}

TEST(strv_make_nulstr_binary) {
        test_strv_make_nulstr_binary_one(NULL, (const char[0]) {}, 0);
        test_strv_make_nulstr_binary_one(STRV_MAKE(NULL), (const char[0]) {}, 0);
        test_strv_make_nulstr_binary_one(STRV_MAKE(""), (const char[1]) { 0 }, 1);
        test_strv_make_nulstr_binary_one(STRV_MAKE("", ""), (const char[2]) { 0, 0 }, 2);
        test_strv_make_nulstr_binary_one(STRV_MAKE("x", ""), (const char[3]) { 'x', 0, 0 }, 3);
        test_strv_make_nulstr_binary_one(STRV_MAKE("", "x"), (const char[3]) { 0, 'x', 0 }, 3);
        test_strv_make_nulstr_binary_one(STRV_MAKE("", "", ""), (const char[3]) { 0, 0, 0 }, 3);
        test_strv_make_nulstr_binary_one(STRV_MAKE("x", "", ""), (const char[4]) { 'x', 0, 0, 0 }, 4);
        test_strv_make_nulstr_binary_one(STRV_MAKE("", "x", ""), (const char[4]) { 0, 'x', 0, 0 }, 4);
        test_strv_make_nulstr_binary_one(STRV_MAKE("", "", "x"), (const char[4]) { 0, 0, 'x', 0 }, 4);
        test_strv_make_nulstr_binary_one(STRV_MAKE("x", "x", ""), (const char[5]) { 'x', 0, 'x', 0, 0 }, 5);
        test_strv_make_nulstr_binary_one(STRV_MAKE("", "x", "x"), (const char[5]) { 0, 'x', 0, 'x', 0 }, 5);
        test_strv_make_nulstr_binary_one(STRV_MAKE("x", "", "x"), (const char[5]) { 'x', 0, 0, 'x', 0 }, 5);
        test_strv_make_nulstr_binary_one(STRV_MAKE("x", "x", "x"), (const char[6]) { 'x', 0, 'x', 0, 'x', 0 }, 6);
}

DEFINE_TEST_MAIN(LOG_INFO);
