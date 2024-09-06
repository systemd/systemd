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

        ASSERT_STREQ(l[0], "str0");
        ASSERT_STREQ(l[1], "str1");
        ASSERT_STREQ(l[2], "str2");
        ASSERT_STREQ(l[3], "str3");
}

#define strv_parse_nulstr_full_one(s, n, e0, e1)                        \
        ({                                                              \
                _cleanup_strv_free_ char **v0 = NULL, **v1 = NULL;      \
                                                                        \
                assert_se(v0 = strv_parse_nulstr_full(s, n, false));    \
                assert_se(strv_equal(v0, e0));                          \
                assert_se(v1 = strv_parse_nulstr_full(s, n, true));     \
                assert_se(strv_equal(v1, e1));                          \
        })

TEST(strv_parse_nulstr_full) {
        const char nulstr1[] = "hoge\0hoge2\0hoge3\0\0hoge5\0\0xxx";
        const char nulstr2[] = "hoge\0hoge2\0hoge3\0\0hoge5\0\0xxx\0\0\0";

        strv_parse_nulstr_full_one(nulstr1, sizeof(nulstr1) - 1,
                                   STRV_MAKE("hoge", "hoge2", "hoge3", "", "hoge5", "", "xxx"),
                                   STRV_MAKE("hoge", "hoge2", "hoge3", "", "hoge5", "", "xxx"));

        strv_parse_nulstr_full_one(nulstr2, sizeof(nulstr2) - 1,
                                   STRV_MAKE("hoge", "hoge2", "hoge3", "", "hoge5", "", "xxx", "", ""),
                                   STRV_MAKE("hoge", "hoge2", "hoge3", "", "hoge5", "", "xxx"));

        strv_parse_nulstr_full_one(((const char[0]) {}), 0,
                                   STRV_MAKE_EMPTY, STRV_MAKE_EMPTY);

        strv_parse_nulstr_full_one(((const char[1]) { 0 }), 1,
                                   STRV_MAKE(""), STRV_MAKE_EMPTY);

        strv_parse_nulstr_full_one(((const char[1]) { 'x' }), 1,
                                   STRV_MAKE("x"), STRV_MAKE("x"));

        strv_parse_nulstr_full_one(((const char[2]) { 0, 0 }), 2,
                                   STRV_MAKE("", ""), STRV_MAKE_EMPTY);

        strv_parse_nulstr_full_one(((const char[2]) { 'x', 0 }), 2,
                                   STRV_MAKE("x"), STRV_MAKE("x"));

        strv_parse_nulstr_full_one(((const char[3]) { 0, 0, 0 }), 3,
                                   STRV_MAKE("", "", ""), STRV_MAKE_EMPTY);

        strv_parse_nulstr_full_one(((const char[3]) { 'x', 0, 0 }), 3,
                                   STRV_MAKE("x", ""), STRV_MAKE("x"));

        strv_parse_nulstr_full_one(((const char[3]) { 0, 'x', 0 }), 3,
                                   STRV_MAKE("", "x"), STRV_MAKE("", "x"));

        strv_parse_nulstr_full_one(((const char[3]) { 0, 0, 'x' }), 3,
                                   STRV_MAKE("", "", "x"), STRV_MAKE("", "", "x"));

        strv_parse_nulstr_full_one(((const char[3]) { 'x', 'x', 0 }), 3,
                                   STRV_MAKE("xx"), STRV_MAKE("xx"));

        strv_parse_nulstr_full_one(((const char[3]) { 0, 'x', 'x' }), 3,
                                   STRV_MAKE("", "xx"), STRV_MAKE("", "xx"));

        strv_parse_nulstr_full_one(((const char[3]) { 'x', 0, 'x' }), 3,
                                   STRV_MAKE("x", "x"), STRV_MAKE("x", "x"));

        strv_parse_nulstr_full_one(((const char[3]) { 'x', 'x', 'x' }), 3,
                                   STRV_MAKE("xxx"), STRV_MAKE("xxx"));
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
                ASSERT_STREQ(s, l[i++]);
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
                static const char expect[] = { 0x00, 0x00 };
                _cleanup_free_ char *nulstr = NULL;

                r = set_make_nulstr(set, &nulstr, &len);
                assert_se(r == 0);
                assert_se(len == 0);
                assert_se(memcmp(expect, nulstr, len + 2) == 0);
        }

        {
                /* Allocated by empty set. */
                static const char expect[] = { 0x00, 0x00 };
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
                static const char expect[] = { 'a', 'a', 'a', 0x00, 0x00 };
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
