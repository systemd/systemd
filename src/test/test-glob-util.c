/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "macro.h"
#include "rm-rf.h"
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

static void closedir_wrapper(void* v) {
        (void) closedir(v);
}

TEST(glob_no_dot) {
        char template[] = "/tmp/test-glob-util.XXXXXXX";
        const char *fn;

        _cleanup_globfree_ glob_t g = {
                .gl_closedir = closedir_wrapper,
                .gl_readdir = (struct dirent *(*)(void *)) readdir_no_dot,
                .gl_opendir = (void *(*)(const char *)) opendir,
                .gl_lstat = lstat,
                .gl_stat = stat,
        };

        int r;

        assert_se(mkdtemp(template));

        fn = strjoina(template, "/*");
        r = glob(fn, GLOB_NOSORT|GLOB_BRACE|GLOB_ALTDIRFUNC, NULL, &g);
        assert_se(r == GLOB_NOMATCH);

        fn = strjoina(template, "/.*");
        r = glob(fn, GLOB_NOSORT|GLOB_BRACE|GLOB_ALTDIRFUNC, NULL, &g);
        assert_se(r == GLOB_NOMATCH);

        (void) rm_rf(template, REMOVE_ROOT|REMOVE_PHYSICAL);
}

TEST(safe_glob) {
        char template[] = "/tmp/test-glob-util.XXXXXXX";
        const char *fn, *fn2, *fname;

        _cleanup_globfree_ glob_t g = {};
        int r;

        assert_se(mkdtemp(template));

        fn = strjoina(template, "/*");
        r = safe_glob(fn, 0, &g);
        assert_se(r == -ENOENT);

        fn2 = strjoina(template, "/.*");
        r = safe_glob(fn2, GLOB_NOSORT|GLOB_BRACE, &g);
        assert_se(r == -ENOENT);

        fname = strjoina(template, "/.foobar");
        assert_se(touch(fname) == 0);

        r = safe_glob(fn, 0, &g);
        assert_se(r == -ENOENT);

        r = safe_glob(fn2, GLOB_NOSORT|GLOB_BRACE, &g);
        assert_se(r == 0);
        assert_se(g.gl_pathc == 1);
        ASSERT_STREQ(g.gl_pathv[0], fname);
        ASSERT_NULL(g.gl_pathv[1]);

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
