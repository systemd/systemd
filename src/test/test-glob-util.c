/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(glob_first) {
        char *first, name[] = "/tmp/test-glob_first.XXXXXX";
        int fd = -EBADF;
        int r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        close(fd);

        r = glob_first("/tmp/test-glob_first*", &first);
        assert_se(r == 1);
        ASSERT_STREQ(name, first);
        first = mfree(first);

        r = unlink(name);
        assert_se(r == 0);
        r = glob_first("/tmp/test-glob_first*", &first);
        assert_se(r == 0);
        ASSERT_NULL(first);
}

TEST(glob_exists) {
        char name[] = "/tmp/test-glob_exists.XXXXXX";
        int fd = -EBADF;
        int r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        close(fd);

        r = glob_exists("/tmp/test-glob_exists*");
        assert_se(r == 1);

        r = unlink(name);
        assert_se(r == 0);
        r = glob_exists("/tmp/test-glob_exists*");
        assert_se(r == 0);
}

TEST(safe_glob) {
        char template[] = "/tmp/test-glob-util.XXXXXXX";
        const char *fn, *fn2, *fname;
        _cleanup_strv_free_ char **v = NULL;

        ASSERT_NOT_NULL(mkdtemp(template));

        fn = strjoina(template, "/*");
        ASSERT_ERROR(safe_glob(fn, /* flags = */ 0, &v), ENOENT);
        ASSERT_ERROR(safe_glob_test(fn, /* flags = */ 0, &v), ENOENT);

        fn2 = strjoina(template, "/.*");
        ASSERT_ERROR(safe_glob(fn2, GLOB_NOSORT|GLOB_BRACE, &v), ENOENT);
        ASSERT_ERROR(safe_glob_test(fn2, GLOB_NOSORT|GLOB_BRACE, &v), ENOENT);

        fname = strjoina(template, "/.foobar");
        ASSERT_OK(touch(fname));

        ASSERT_ERROR(safe_glob(fn, /* flags = */ 0, &v), ENOENT);
        ASSERT_ERROR(safe_glob_test(fn, /* flags = */ 0, &v), ENOENT);

        ASSERT_OK(safe_glob(fn2, GLOB_NOSORT|GLOB_BRACE, &v));
        ASSERT_EQ(strv_length(v), 1u);
        ASSERT_STREQ(v[0], fname);
        ASSERT_NULL(v[1]);

        v = strv_free(v);

        ASSERT_OK(safe_glob_test(fn2, GLOB_NOSORT|GLOB_BRACE, &v));
        ASSERT_EQ(strv_length(v), 1u);
        ASSERT_STREQ(v[0], fname);
        ASSERT_NULL(v[1]);

        (void) rm_rf(template, REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_glob_non_glob_prefix_one(const char *path, const char *expected) {
        _cleanup_free_ char *t;

        assert_se(glob_non_glob_prefix(path, &t) == 0);
        ASSERT_STREQ(t, expected);
}

TEST(glob_non_glob) {
        test_glob_non_glob_prefix_one("/tmp/.X11-*", "/tmp/");
        test_glob_non_glob_prefix_one("/tmp/*", "/tmp/");
        test_glob_non_glob_prefix_one("/tmp*", "/");
        test_glob_non_glob_prefix_one("/tmp/*/whatever", "/tmp/");
        test_glob_non_glob_prefix_one("/tmp/*/whatever?", "/tmp/");
        test_glob_non_glob_prefix_one("/?", "/");

        char *x;
        assert_se(glob_non_glob_prefix("?", &x) == -ENOENT);
}

DEFINE_TEST_MAIN(LOG_INFO);
