/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_tempfn_random_one(const char *p, const char *extra, const char *expect, int ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = tempfn_random(p, extra, &s);
        log_info("%s+%s → %s vs. %s (%i/%s vs. %i/%s)",
                 p, strna(extra), strna(s), strna(expect),
                 r, STRERROR(r), ret, STRERROR(ret));

        assert_se(!s == !expect);
        if (s) {
                const char *suffix;

                assert_se(suffix = startswith(s, expect));
                assert_se(in_charset(suffix, HEXDIGITS));
                assert_se(strlen(suffix) == 16);
        }
        assert_se(ret == r);
}

TEST(tempfn_random) {
        _cleanup_free_ char *dir = NULL, *p = NULL, *q = NULL;

        test_tempfn_random_one("", NULL, NULL, -EINVAL);
        test_tempfn_random_one(".", NULL, NULL, -EADDRNOTAVAIL);
        test_tempfn_random_one("..", NULL, NULL, -EINVAL);
        test_tempfn_random_one("/", NULL, NULL, -EADDRNOTAVAIL);
        test_tempfn_random_one("foo", "hoge/aaa", NULL, -EINVAL);

        test_tempfn_random_one("foo", NULL, ".#foo", 0);
        test_tempfn_random_one("foo", "bar", ".#barfoo", 0);
        test_tempfn_random_one("/tmp/foo", NULL, "/tmp/.#foo", 0);
        test_tempfn_random_one("/tmp/foo", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_random_one("./foo", NULL, ".#foo", 0);
        test_tempfn_random_one("./foo", "bar", ".#barfoo", 0);
        test_tempfn_random_one("../foo", NULL, "../.#foo", 0);
        test_tempfn_random_one("../foo", "bar", "../.#barfoo", 0);

        test_tempfn_random_one("foo/", NULL, ".#foo", 0);
        test_tempfn_random_one("foo/", "bar", ".#barfoo", 0);
        test_tempfn_random_one("/tmp/foo/", NULL, "/tmp/.#foo", 0);
        test_tempfn_random_one("/tmp/foo/", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_random_one("./foo/", NULL, ".#foo", 0);
        test_tempfn_random_one("./foo/", "bar", ".#barfoo", 0);
        test_tempfn_random_one("../foo/", NULL, "../.#foo", 0);
        test_tempfn_random_one("../foo/", "bar", "../.#barfoo", 0);

        assert_se(dir = new(char, PATH_MAX - 20));
        memset(dir, 'x', PATH_MAX - 21);
        dir[PATH_MAX - 21] = '\0';
        for (size_t i = 0; i < PATH_MAX - 21; i += NAME_MAX + 1)
                dir[i] = '/';

        assert_se(p = path_join(dir, "a"));
        assert_se(q = path_join(dir, ".#a"));

        test_tempfn_random_one(p, NULL, q, 0);
        test_tempfn_random_one(p, "b", NULL, -EINVAL);

        p = mfree(p);
        q = mfree(q);

        assert_se(p = new(char, NAME_MAX + 1));
        memset(p, 'x', NAME_MAX);
        p[NAME_MAX] = '\0';

        assert_se(q = new(char, NAME_MAX + 1));
        memset(stpcpy(q, ".#"), 'x', NAME_MAX - STRLEN(".#") - 16);
        q[NAME_MAX - 16] = '\0';

        test_tempfn_random_one(p, NULL, q, 0);

        memset(stpcpy(q, ".#hoge"), 'x', NAME_MAX - STRLEN(".#hoge") - 16);
        q[NAME_MAX - 16] = '\0';

        test_tempfn_random_one(p, "hoge", q, 0);
}

static void test_tempfn_xxxxxx_one(const char *p, const char *extra, const char *expect, int ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = tempfn_xxxxxx(p, extra, &s);
        log_info("%s+%s → %s vs. %s (%i/%s vs. %i/%s)",
                 p, strna(extra), strna(s), strna(expect),
                 r, STRERROR(r), ret, STRERROR(ret));

        assert_se(!s == !expect);
        if (s) {
                const char *suffix;

                assert_se(suffix = startswith(s, expect));
                assert_se(streq(suffix, "XXXXXX"));
        }
        assert_se(ret == r);
}

TEST(tempfn_xxxxxx) {
        _cleanup_free_ char *dir = NULL, *p = NULL, *q = NULL;

        test_tempfn_xxxxxx_one("", NULL, NULL, -EINVAL);
        test_tempfn_xxxxxx_one(".", NULL, NULL, -EADDRNOTAVAIL);
        test_tempfn_xxxxxx_one("..", NULL, NULL, -EINVAL);
        test_tempfn_xxxxxx_one("/", NULL, NULL, -EADDRNOTAVAIL);
        test_tempfn_xxxxxx_one("foo", "hoge/aaa", NULL, -EINVAL);

        test_tempfn_xxxxxx_one("foo", NULL, ".#foo", 0);
        test_tempfn_xxxxxx_one("foo", "bar", ".#barfoo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo", NULL, "/tmp/.#foo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_xxxxxx_one("./foo", NULL, ".#foo", 0);
        test_tempfn_xxxxxx_one("./foo", "bar", ".#barfoo", 0);
        test_tempfn_xxxxxx_one("../foo", NULL, "../.#foo", 0);
        test_tempfn_xxxxxx_one("../foo", "bar", "../.#barfoo", 0);

        test_tempfn_xxxxxx_one("foo/", NULL, ".#foo", 0);
        test_tempfn_xxxxxx_one("foo/", "bar", ".#barfoo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo/", NULL, "/tmp/.#foo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo/", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_xxxxxx_one("./foo/", NULL, ".#foo", 0);
        test_tempfn_xxxxxx_one("./foo/", "bar", ".#barfoo", 0);
        test_tempfn_xxxxxx_one("../foo/", NULL, "../.#foo", 0);
        test_tempfn_xxxxxx_one("../foo/", "bar", "../.#barfoo", 0);

        assert_se(dir = new(char, PATH_MAX - 10));
        memset(dir, 'x', PATH_MAX - 11);
        dir[PATH_MAX - 11] = '\0';
        for (size_t i = 0; i < PATH_MAX - 11; i += NAME_MAX + 1)
                dir[i] = '/';

        assert_se(p = path_join(dir, "a"));
        assert_se(q = path_join(dir, ".#a"));

        test_tempfn_xxxxxx_one(p, NULL, q, 0);
        test_tempfn_xxxxxx_one(p, "b", NULL, -EINVAL);

        p = mfree(p);
        q = mfree(q);

        assert_se(p = new(char, NAME_MAX + 1));
        memset(p, 'x', NAME_MAX);
        p[NAME_MAX] = '\0';

        assert_se(q = new(char, NAME_MAX + 1));
        memset(stpcpy(q, ".#"), 'x', NAME_MAX - STRLEN(".#") - 6);
        q[NAME_MAX - 6] = '\0';

        test_tempfn_xxxxxx_one(p, NULL, q, 0);

        memset(stpcpy(q, ".#hoge"), 'x', NAME_MAX - STRLEN(".#hoge") - 6);
        q[NAME_MAX - 6] = '\0';

        test_tempfn_xxxxxx_one(p, "hoge", q, 0);
}

static void test_tempfn_random_child_one(const char *p, const char *extra, const char *expect, int ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = tempfn_random_child(p, extra, &s);
        log_info_errno(r, "%s+%s → %s vs. %s (%i/%s vs. %i/%s)",
                       p, strna(extra), strna(s), strna(expect),
                       r, STRERROR(r), ret, STRERROR(ret));

        assert_se(!s == !expect);
        if (s) {
                const char *suffix;

                assert_se(suffix = startswith(s, expect));
                assert_se(in_charset(suffix, HEXDIGITS));
                assert_se(strlen(suffix) == 16);
        }
        assert_se(ret == r);
}

TEST(tempfn_random_child) {
        _cleanup_free_ char *dir = NULL, *p = NULL, *q = NULL;

        test_tempfn_random_child_one("", NULL, ".#", 0);
        test_tempfn_random_child_one(".", NULL, ".#", 0);
        test_tempfn_random_child_one("..", NULL, "../.#", 0);
        test_tempfn_random_child_one("/", NULL, "/.#", 0);
        test_tempfn_random_child_one("foo", "hoge/aaa", NULL, -EINVAL);

        test_tempfn_random_child_one("foo", NULL, "foo/.#", 0);
        test_tempfn_random_child_one("foo", "bar", "foo/.#bar", 0);
        test_tempfn_random_child_one("/tmp/foo", NULL, "/tmp/foo/.#", 0);
        test_tempfn_random_child_one("/tmp/foo", "bar", "/tmp/foo/.#bar", 0);
        test_tempfn_random_child_one("./foo", NULL, "foo/.#", 0);
        test_tempfn_random_child_one("./foo", "bar", "foo/.#bar", 0);
        test_tempfn_random_child_one("../foo", NULL, "../foo/.#", 0);
        test_tempfn_random_child_one("../foo", "bar", "../foo/.#bar", 0);

        test_tempfn_random_child_one("foo/", NULL, "foo/.#", 0);
        test_tempfn_random_child_one("foo/", "bar", "foo/.#bar", 0);
        test_tempfn_random_child_one("/tmp/foo/", NULL, "/tmp/foo/.#", 0);
        test_tempfn_random_child_one("/tmp/foo/", "bar", "/tmp/foo/.#bar", 0);
        test_tempfn_random_child_one("./foo/", NULL, "foo/.#", 0);
        test_tempfn_random_child_one("./foo/", "bar", "foo/.#bar", 0);
        test_tempfn_random_child_one("../foo/", NULL, "../foo/.#", 0);
        test_tempfn_random_child_one("../foo/", "bar", "../foo/.#bar", 0);

        assert_se(dir = new(char, PATH_MAX - 21));
        memset(dir, 'x', PATH_MAX - 22);
        dir[PATH_MAX - 22] = '\0';
        for (size_t i = 0; i < PATH_MAX - 22; i += NAME_MAX + 1)
                dir[i] = '/';

        assert_se(p = path_join(dir, "a"));
        assert_se(q = path_join(p, ".#"));

        test_tempfn_random_child_one(p, NULL, q, 0);
        test_tempfn_random_child_one(p, "b", NULL, -EINVAL);

        p = mfree(p);
        q = mfree(q);

        assert_se(p = new(char, NAME_MAX + 1));
        memset(p, 'x', NAME_MAX);
        p[NAME_MAX] = '\0';

        assert_se(q = path_join(p, ".#"));

        test_tempfn_random_child_one(p, NULL, q, 0);

        assert_se(strextend(&q, "hoge"));
        test_tempfn_random_child_one(p, "hoge", q, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
