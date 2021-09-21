/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "hash-funcs.h"
#include "io-util.h"
#include "set.h"

static void test_path_hash_set(void) {
        /* The goal is to make sure that non-simplified path are hashed as expected,
         * and that we don't need to simplify them beforehand. */

        log_info("/* %s */", __func__);

        /* No freeing of keys, we operate on static strings here… */
        _cleanup_set_free_ Set *set = NULL;

        assert_se(set_isempty(set));
        assert_se(set_ensure_put(&set, &path_hash_ops, "foo") == 1);
        assert_se(set_ensure_put(&set, &path_hash_ops, "foo") == 0);
        assert_se(set_ensure_put(&set, &path_hash_ops, "bar") == 1);
        assert_se(set_ensure_put(&set, &path_hash_ops, "bar") == 0);
        assert_se(set_ensure_put(&set, &path_hash_ops, "/foo") == 1);
        assert_se(set_ensure_put(&set, &path_hash_ops, "/bar") == 1);
        assert_se(set_ensure_put(&set, &path_hash_ops, "/foo/.") == 0);
        assert_se(set_ensure_put(&set, &path_hash_ops, "/./bar/./.") == 0);

        assert_se(set_contains(set, "foo"));
        assert_se(set_contains(set, "bar"));
        assert_se(set_contains(set, "./foo"));
        assert_se(set_contains(set, "./foo/."));
        assert_se(set_contains(set, "./bar"));
        assert_se(set_contains(set, "./bar/."));
        assert_se(set_contains(set, "/foo"));
        assert_se(set_contains(set, "/bar"));
        assert_se(set_contains(set, "//./foo"));
        assert_se(set_contains(set, "///./foo/."));
        assert_se(set_contains(set, "////./bar"));
        assert_se(set_contains(set, "/////./bar/."));

        assert_se(set_contains(set, "foo/"));
        assert_se(set_contains(set, "bar/"));
        assert_se(set_contains(set, "./foo/"));
        assert_se(set_contains(set, "./foo/./"));
        assert_se(set_contains(set, "./bar/"));
        assert_se(set_contains(set, "./bar/./"));
        assert_se(set_contains(set, "/foo/"));
        assert_se(set_contains(set, "/bar/"));
        assert_se(set_contains(set, "//./foo/"));
        assert_se(set_contains(set, "///./foo/./"));
        assert_se(set_contains(set, "////./bar/"));
        assert_se(set_contains(set, "/////./bar/./"));

        assert_se(!set_contains(set, "foo."));
        assert_se(!set_contains(set, ".bar"));
        assert_se(!set_contains(set, "./foo."));
        assert_se(!set_contains(set, "./.foo/."));
        assert_se(!set_contains(set, "../bar"));
        assert_se(!set_contains(set, "./bar/.."));
        assert_se(!set_contains(set, "./foo.."));
        assert_se(!set_contains(set, "/..bar"));
        assert_se(!set_contains(set, "//../foo"));
        assert_se(!set_contains(set, "///../foo/."));
        assert_se(!set_contains(set, "////../bar"));
        assert_se(!set_contains(set, "/////../bar/."));

        assert_se(!set_contains(set, "foo./"));
        assert_se(!set_contains(set, ".bar/"));
        assert_se(!set_contains(set, "./foo./"));
        assert_se(!set_contains(set, "./.foo/./"));
        assert_se(!set_contains(set, "../bar/"));
        assert_se(!set_contains(set, "./bar/../"));
        assert_se(!set_contains(set, "./foo../"));
        assert_se(!set_contains(set, "/..bar/"));
        assert_se(!set_contains(set, "//../foo/"));
        assert_se(!set_contains(set, "///../foo/./"));
        assert_se(!set_contains(set, "////../bar/"));
        assert_se(!set_contains(set, "/////../bar/./"));
}

static int iovec_compare_strings(const char *a, const char *b) {
        return iovec_compare_func(&IOVEC_MAKE_STRING(a), &IOVEC_MAKE_STRING(b));
}

static void test_iovec_compare(void) {
        log_info("/* %s */", __func__);

        assert_se(iovec_compare_strings("foo", "foo") == 0);
        assert_se(iovec_compare_strings("foo", "bar") > 0);
        assert_se(iovec_compare_strings("bar", "foo") < 0);
        assert_se(iovec_compare_strings("foo", "foobar") < 0);
        assert_se(iovec_compare_strings("foobar", "foo") > 0);
}

static void test_iovec_hash_set(void) {
        log_info("/* %s */", __func__);

        _cleanup_set_free_free_ Set *set = NULL;

        assert_se(iovec_set_ensure_put_string(&set, &iovec_hash_ops_free, "foo") == 1);
        assert_se(iovec_set_ensure_put_string(&set, &iovec_hash_ops_free, "foo") == 0);
        assert_se(iovec_set_ensure_put_string(&set, &iovec_hash_ops_free, "bar") == 1);
        assert_se(iovec_set_ensure_put_string(&set, &iovec_hash_ops_free, "bar") == 0);
        assert_se(iovec_set_ensure_put_string(&set, &iovec_hash_ops_free, "foobar") == 1);
        assert_se(iovec_set_ensure_put_string(&set, &iovec_hash_ops_free, "foobar") == 0);

        assert_se(set_contains(set, &IOVEC_MAKE_STRING("foo")));
        assert_se(set_contains(set, &IOVEC_MAKE_STRING("bar")));
        assert_se(set_contains(set, &IOVEC_MAKE_STRING("foobar")));
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_path_hash_set();
        test_iovec_compare();
        test_iovec_hash_set();
}
