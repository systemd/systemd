/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_tempfn_random_one(const char *p, const char *extra, const char *expect, int ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = tempfn_random(p, extra, &s);
        log_info_errno(r, "%s+%s → %s vs. %s (%i/%m vs. %i/%s)", p, strna(extra), strna(s), strna(expect), r, ret, strerror_safe(ret));

        assert(!s == !expect);
        if (s) {
                const char *suffix;

                assert_se(suffix = startswith(s, expect));
                assert_se(in_charset(suffix, HEXDIGITS));
                assert_se(strlen(suffix) == 16);
        }
        assert(ret == r);
}

static void test_tempfn_random(void) {
        test_tempfn_random_one("", NULL, NULL, -EINVAL);
        test_tempfn_random_one(".", NULL, NULL, -EINVAL);
        test_tempfn_random_one("..", NULL, NULL, -EINVAL);
        test_tempfn_random_one("/", NULL, NULL, -EADDRNOTAVAIL);

        test_tempfn_random_one("foo", NULL, ".#foo", 0);
        test_tempfn_random_one("foo", "bar", ".#barfoo", 0);
        test_tempfn_random_one("/tmp/foo", NULL, "/tmp/.#foo", 0);
        test_tempfn_random_one("/tmp/foo", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_random_one("./foo", NULL, "./.#foo", 0);
        test_tempfn_random_one("./foo", "bar", "./.#barfoo", 0);
        test_tempfn_random_one("../foo", NULL, "../.#foo", 0);
        test_tempfn_random_one("../foo", "bar", "../.#barfoo", 0);

        test_tempfn_random_one("foo/", NULL, ".#foo", 0);
        test_tempfn_random_one("foo/", "bar", ".#barfoo", 0);
        test_tempfn_random_one("/tmp/foo/", NULL, "/tmp/.#foo", 0);
        test_tempfn_random_one("/tmp/foo/", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_random_one("./foo/", NULL, "./.#foo", 0);
        test_tempfn_random_one("./foo/", "bar", "./.#barfoo", 0);
        test_tempfn_random_one("../foo/", NULL, "../.#foo", 0);
        test_tempfn_random_one("../foo/", "bar", "../.#barfoo", 0);
}

static void test_tempfn_xxxxxx_one(const char *p, const char *extra, const char *expect, int ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = tempfn_xxxxxx(p, extra, &s);
        log_info_errno(r, "%s+%s → %s vs. %s (%i/%m vs. %i/%s)", p, strna(extra), strna(s), strna(expect), r, ret, strerror_safe(ret));

        assert(!s == !expect);
        if (s) {
                const char *suffix;

                assert_se(suffix = startswith(s, expect));
                assert_se(streq(suffix, "XXXXXX"));
        }
        assert(ret == r);
}

static void test_tempfn_xxxxxx(void) {
        test_tempfn_xxxxxx_one("", NULL, NULL, -EINVAL);
        test_tempfn_xxxxxx_one(".", NULL, NULL, -EINVAL);
        test_tempfn_xxxxxx_one("..", NULL, NULL, -EINVAL);
        test_tempfn_xxxxxx_one("/", NULL, NULL, -EADDRNOTAVAIL);

        test_tempfn_xxxxxx_one("foo", NULL, ".#foo", 0);
        test_tempfn_xxxxxx_one("foo", "bar", ".#barfoo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo", NULL, "/tmp/.#foo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_xxxxxx_one("./foo", NULL, "./.#foo", 0);
        test_tempfn_xxxxxx_one("./foo", "bar", "./.#barfoo", 0);
        test_tempfn_xxxxxx_one("../foo", NULL, "../.#foo", 0);
        test_tempfn_xxxxxx_one("../foo", "bar", "../.#barfoo", 0);

        test_tempfn_xxxxxx_one("foo/", NULL, ".#foo", 0);
        test_tempfn_xxxxxx_one("foo/", "bar", ".#barfoo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo/", NULL, "/tmp/.#foo", 0);
        test_tempfn_xxxxxx_one("/tmp/foo/", "bar", "/tmp/.#barfoo", 0);
        test_tempfn_xxxxxx_one("./foo/", NULL, "./.#foo", 0);
        test_tempfn_xxxxxx_one("./foo/", "bar", "./.#barfoo", 0);
        test_tempfn_xxxxxx_one("../foo/", NULL, "../.#foo", 0);
        test_tempfn_xxxxxx_one("../foo/", "bar", "../.#barfoo", 0);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_tempfn_random();
        test_tempfn_xxxxxx();

        return 0;
}
