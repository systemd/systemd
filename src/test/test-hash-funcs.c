/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "hash-funcs.h"
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

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_path_hash_set();
}
