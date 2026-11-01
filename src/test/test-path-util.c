/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "errno-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(print_paths) {
        log_info("default system PATH: %s", default_PATH());
        log_info("default user PATH: %s", default_user_PATH());
}

TEST(path) {
        ASSERT_FALSE(path_is_absolute(NULL));
        ASSERT_FALSE(path_is_absolute(""));
        ASSERT_TRUE(path_is_absolute("/"));
        ASSERT_TRUE(path_is_absolute("//"));
        ASSERT_FALSE(path_is_absolute("./"));
        ASSERT_FALSE(path_is_absolute("foo/bar"));

        ASSERT_TRUE(PATH_IN_SET("/bin", "/", "/bin", "/foo"));
        ASSERT_TRUE(PATH_IN_SET("/bin", "/bin"));
        ASSERT_TRUE(PATH_IN_SET("/bin", "/foo/bar", "/bin"));
        ASSERT_TRUE(PATH_IN_SET("/", "/", "/", "/foo/bar"));
        ASSERT_FALSE(PATH_IN_SET("/", "/abc", "/def"));

        ASSERT_PATH_EQ(NULL, NULL);
        ASSERT_PATH_EQ("/a", "/a");
        ASSERT_FALSE(path_equal("/a", "/b"));
        ASSERT_FALSE(path_equal("/a", NULL));
        ASSERT_FALSE(path_equal(NULL, "/a"));
        ASSERT_FALSE(path_equal("a", NULL));
        ASSERT_FALSE(path_equal(NULL, "a"));
}

TEST(path_is_normalized) {
        ASSERT_TRUE(path_is_normalized("/"));
        ASSERT_TRUE(path_is_normalized("/usr/bin"));
        ASSERT_TRUE(path_is_normalized("usr/bin"));

        ASSERT_FALSE(path_is_normalized(""));
        ASSERT_FALSE(path_is_normalized("."));
        ASSERT_FALSE(path_is_normalized("./usr/bin"));
        ASSERT_FALSE(path_is_normalized("/usr//bin"));
        ASSERT_FALSE(path_is_normalized("/usr/./bin"));
        ASSERT_FALSE(path_is_normalized("/usr/bin/."));
        ASSERT_FALSE(path_is_normalized("../usr/bin"));
        ASSERT_FALSE(path_is_normalized("/usr/../bin"));
}

TEST(is_path) {
        ASSERT_FALSE(is_path("foo"));
        ASSERT_FALSE(is_path("dos.ext"));
        ASSERT_TRUE(is_path("/dir"));
        ASSERT_TRUE(is_path("a/b"));
        ASSERT_TRUE(is_path("a/b.ext"));

        ASSERT_FALSE(is_path("."));
        ASSERT_FALSE(is_path(""));
        ASSERT_FALSE(is_path(".."));

        ASSERT_TRUE(is_path("/dev"));
        ASSERT_TRUE(is_path("/./dev"));
        ASSERT_TRUE(is_path("/./dev/."));
        ASSERT_TRUE(is_path("/./dev."));
        ASSERT_TRUE(is_path("//dev"));
        ASSERT_TRUE(is_path("///dev"));
        ASSERT_TRUE(is_path("/dev/"));
        ASSERT_TRUE(is_path("///dev/"));
        ASSERT_TRUE(is_path("/./dev/"));
        ASSERT_TRUE(is_path("/../dev/"));
        ASSERT_TRUE(is_path("/dev/sda"));
        ASSERT_TRUE(is_path("/dev/sda5"));
        ASSERT_TRUE(is_path("/dev/sda5b3"));
        ASSERT_TRUE(is_path("/dev/sda5b3/idontexit"));
        ASSERT_TRUE(is_path("/../dev/sda"));
        ASSERT_TRUE(is_path("/../../dev/sda5"));
        ASSERT_TRUE(is_path("/../../../dev/sda5b3"));
        ASSERT_TRUE(is_path("/.././.././dev/sda5b3/idontexit"));
        ASSERT_TRUE(is_path("/sys"));
        ASSERT_TRUE(is_path("/sys/"));
        ASSERT_TRUE(is_path("/./sys"));
        ASSERT_TRUE(is_path("/./sys/."));
        ASSERT_TRUE(is_path("/./sys."));
        ASSERT_TRUE(is_path("/sys/what"));
        ASSERT_TRUE(is_path("/sys/something/.."));
        ASSERT_TRUE(is_path("/sys/something/../"));
        ASSERT_TRUE(is_path("/sys////"));
        ASSERT_TRUE(is_path("/sys////."));
        ASSERT_TRUE(is_path("/sys/.."));
        ASSERT_TRUE(is_path("/sys/../"));
        ASSERT_TRUE(is_path("/usr/../dev/sda"));
}

TEST(is_device_path) {
        ASSERT_FALSE(is_device_path("foo"));
        ASSERT_FALSE(is_device_path("dos.ext"));
        ASSERT_FALSE(is_device_path("/dir"));
        ASSERT_FALSE(is_device_path("a/b"));
        ASSERT_FALSE(is_device_path("a/b.ext"));

        ASSERT_FALSE(is_device_path("."));
        ASSERT_FALSE(is_device_path(""));
        ASSERT_FALSE(is_device_path(".."));

        ASSERT_FALSE(is_device_path("/dev"));
        ASSERT_FALSE(is_device_path("/./dev"));
        ASSERT_FALSE(is_device_path("/./dev/."));
        ASSERT_FALSE(is_device_path("/./dev."));
        ASSERT_TRUE(is_device_path("/./dev/foo"));
        ASSERT_TRUE(is_device_path("/./dev/./foo"));
        ASSERT_FALSE(is_device_path("/./dev./foo"));
        ASSERT_FALSE(is_device_path("//dev"));
        ASSERT_FALSE(is_device_path("///dev"));
        ASSERT_FALSE(is_device_path("/dev/"));
        ASSERT_FALSE(is_device_path("///dev/"));
        ASSERT_FALSE(is_device_path("/./dev/"));
        ASSERT_FALSE(is_device_path("/../dev/"));
        ASSERT_TRUE(is_device_path("/dev/sda"));
        ASSERT_TRUE(is_device_path("/dev/sda5"));
        ASSERT_TRUE(is_device_path("/dev/sda5b3"));
        ASSERT_TRUE(is_device_path("/dev/sda5b3/idontexit"));
        ASSERT_FALSE(is_device_path("/../dev/sda"));
        ASSERT_FALSE(is_device_path("/../../dev/sda5"));
        ASSERT_FALSE(is_device_path("/../../../dev/sda5b3"));
        ASSERT_FALSE(is_device_path("/.././.././dev/sda5b3/idontexit"));
        ASSERT_FALSE(is_device_path("/sys"));
        ASSERT_FALSE(is_device_path("/sys/"));
        ASSERT_FALSE(is_device_path("/./sys"));
        ASSERT_FALSE(is_device_path("/./sys/."));
        ASSERT_FALSE(is_device_path("/./sys."));
        ASSERT_TRUE(is_device_path("/./sys/foo"));
        ASSERT_TRUE(is_device_path("/./sys/./foo"));
        ASSERT_FALSE(is_device_path("/./sys./foo"));
        ASSERT_TRUE(is_device_path("/sys/what"));
        ASSERT_TRUE(is_device_path("/sys/something/.."));
        ASSERT_TRUE(is_device_path("/sys/something/../"));
        ASSERT_FALSE(is_device_path("/sys////"));
        ASSERT_FALSE(is_device_path("/sys////."));
        ASSERT_TRUE(is_device_path("/sys/.."));
        ASSERT_TRUE(is_device_path("/sys/../"));
        ASSERT_FALSE(is_device_path("/usr/../dev/sda"));
}

static void test_path_simplify_one(const char *in, const char *out, PathSimplifyFlags flags) {
        char *p;

        p = strdupa_safe(in);
        path_simplify_full(p, flags);
        log_debug("/* test_path_simplify(%s) → %s (expected: %s) */", in, p, out);
        ASSERT_STREQ(p, out);
}

TEST(path_simplify) {
        _cleanup_free_ char *hoge = NULL, *hoge_out = NULL;
        char foo[NAME_MAX * 2];

        test_path_simplify_one("", "", /* flags= */ 0);
        test_path_simplify_one("aaa/bbb////ccc", "aaa/bbb/ccc", /* flags= */ 0);
        test_path_simplify_one("//aaa/.////ccc", "/aaa/ccc", /* flags= */ 0);
        test_path_simplify_one("///", "/", /* flags= */ 0);
        test_path_simplify_one("///", "/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("///.//", "/", /* flags= */ 0);
        test_path_simplify_one("///.//.///", "/", /* flags= */ 0);
        test_path_simplify_one("////.././///../.", "/", /* flags= */ 0);
        test_path_simplify_one(".", ".", /* flags= */ 0);
        test_path_simplify_one("./", ".", /* flags= */ 0);
        test_path_simplify_one("./", "./", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one(".///.//./.", ".", /* flags= */ 0);
        test_path_simplify_one(".///.//././/", ".", /* flags= */ 0);
        test_path_simplify_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.",
                               "/aaa/.bbb/../c./d.dd/..eeee", /* flags= */ 0);
        test_path_simplify_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                               "/aaa/.bbb/../c./d.dd/..eeee/..", /* flags= */ 0);
        test_path_simplify_one(".//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                               "aaa/.bbb/../c./d.dd/..eeee/..", /* flags= */ 0);
        test_path_simplify_one("..//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                               "../aaa/.bbb/../c./d.dd/..eeee/..", /* flags= */ 0);
        test_path_simplify_one("abc///", "abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);

        test_path_simplify_one("/../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///", "/abc", /* flags= */ 0);
        test_path_simplify_one("/../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///..", "/abc/..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///../", "/abc/../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///../", "/abc/..", /* flags= */ 0);

        test_path_simplify_one("/../../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///", "/abc", /* flags= */ 0);
        test_path_simplify_one("/../../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///../..", "/abc/../..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///../../", "/abc/../../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///../../", "/abc/../..", /* flags= */ 0);

        test_path_simplify_one("/.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///", "/abc", /* flags= */ 0);
        test_path_simplify_one("/.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///../..", "/abc/../..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///../../", "/abc/../../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///../../", "/abc/../..", /* flags= */ 0);

        test_path_simplify_one("/./.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///", "/abc", /* flags= */ 0);
        test_path_simplify_one("/./.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///../..", "/abc/../..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///../../", "/abc/../../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///../../", "/abc/../..", /* flags= */ 0);

        test_path_simplify_one("/.../abc", "/.../abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///", "/.../abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///", "/.../abc", /* flags= */ 0);
        test_path_simplify_one("/.../abc", "/.../abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///...", "/.../abc/...", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///.../", "/.../abc/.../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///.../", "/.../abc/...", /* flags= */ 0);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_simplify_one(foo, foo, /* flags= */ 0);

        hoge = ASSERT_NOT_NULL(strjoin("/", foo));
        test_path_simplify_one(hoge, hoge, /* flags= */ 0);
        hoge = mfree(hoge);

        hoge = ASSERT_NOT_NULL(strjoin("a////.//././//./b///././/./c/////././//./", foo,
                                       "//.//////d/e/.//f/"));

        hoge_out = ASSERT_NOT_NULL(strjoin("a/b/c/", foo, "//.//////d/e/.//f/"));

        test_path_simplify_one(hoge, hoge_out, /* flags= */ 0);
}

static void test_path_compare_one(const char *a, const char *b, int expected) {
        int r;

        ASSERT_EQ(path_compare(a, a), 0);
        ASSERT_EQ(path_compare(b, b), 0);

        r = path_compare(a, b);
        ASSERT_EQ(r > 0, expected > 0);
        ASSERT_EQ(r < 0, expected < 0);
        r = path_compare(b, a);
        ASSERT_EQ(r < 0, expected > 0);
        ASSERT_EQ(r > 0, expected < 0);

        ASSERT_TRUE(path_equal(a, a));
        ASSERT_TRUE(path_equal(b, b));
        ASSERT_EQ(path_equal(a, b), expected == 0);
        ASSERT_EQ(path_equal(b, a), expected == 0);
}

TEST(path_compare) {
        test_path_compare_one("/goo", "/goo", /* expected= */ 0);
        test_path_compare_one("/goo", "/goo", /* expected= */ 0);
        test_path_compare_one("//goo", "/goo", /* expected= */ 0);
        test_path_compare_one("//goo/////", "/goo", /* expected= */ 0);
        test_path_compare_one("goo/////", "goo", /* expected= */ 0);
        test_path_compare_one("/goo/boo", "/goo//boo", /* expected= */ 0);
        test_path_compare_one("//goo/boo", "/goo/boo//", /* expected= */ 0);
        test_path_compare_one("//goo/././//./boo//././//", "/goo/boo//.", /* expected= */ 0);
        test_path_compare_one("/.", "//.///", /* expected= */ 0);
        test_path_compare_one("/x", "x/", 1);
        test_path_compare_one("x/", "/", -1);
        test_path_compare_one("/x/./y", "x/y", 1);
        test_path_compare_one("/x/./y", "/x/y", /* expected= */ 0);
        test_path_compare_one("/x/./././y", "/x/y/././.", /* expected= */ 0);
        test_path_compare_one("./x/./././y", "./x/y/././.", /* expected= */ 0);
        test_path_compare_one(".", "./.", /* expected= */ 0);
        test_path_compare_one(".", "././.", /* expected= */ 0);
        test_path_compare_one("./..", ".", 1);
        test_path_compare_one("x/.y", "x/y", -1);
        test_path_compare_one("foo", "/foo", -1);
        test_path_compare_one("/foo", "/foo/bar", -1);
        test_path_compare_one("/foo/aaa", "/foo/b", -1);
        test_path_compare_one("/foo/aaa", "/foo/b/a", -1);
        test_path_compare_one("/foo/a", "/foo/aaa", -1);
        test_path_compare_one("/foo/a/b", "/foo/aaa", -1);
}

static void test_path_compare_filename_one(const char *a, const char *b, int expected) {
        int r;

        ASSERT_EQ(path_compare_filename(a, a), 0);
        ASSERT_EQ(path_compare_filename(b, b), 0);

        r = path_compare_filename(a, b);
        ASSERT_EQ(r > 0, expected > 0);
        ASSERT_EQ(r < 0, expected < 0);
        r = path_compare_filename(b, a);
        ASSERT_EQ(r < 0, expected > 0);
        ASSERT_EQ(r > 0, expected < 0);

        ASSERT_TRUE(path_equal_filename(a, a));
        ASSERT_TRUE(path_equal_filename(b, b));
        ASSERT_EQ(path_equal_filename(a, b), expected == 0);
        ASSERT_EQ(path_equal_filename(b, a), expected == 0);
}

TEST(path_compare_filename) {
        test_path_compare_filename_one("/goo", "/goo", /* expected= */ 0);
        test_path_compare_filename_one("/goo", "/goo", /* expected= */ 0);
        test_path_compare_filename_one("//goo", "/goo", /* expected= */ 0);
        test_path_compare_filename_one("//goo/////", "/goo", /* expected= */ 0);
        test_path_compare_filename_one("goo/////", "goo", /* expected= */ 0);
        test_path_compare_filename_one("/goo/boo", "/goo//boo", /* expected= */ 0);
        test_path_compare_filename_one("//goo/boo", "/goo/boo//", /* expected= */ 0);
        test_path_compare_filename_one("//goo/././//./boo//././//", "/goo/boo//.", /* expected= */ 0);
        test_path_compare_filename_one("/.", "//.///", -1);
        test_path_compare_filename_one("/x", "x/", /* expected= */ 0);
        test_path_compare_filename_one("x/", "/", 1);
        test_path_compare_filename_one("/x/./y", "x/y", /* expected= */ 0);
        test_path_compare_filename_one("/x/./y", "/x/y", /* expected= */ 0);
        test_path_compare_filename_one("/x/./././y", "/x/y/././.", /* expected= */ 0);
        test_path_compare_filename_one("./x/./././y", "./x/y/././.", /* expected= */ 0);
        test_path_compare_filename_one(".", "./.", -1);
        test_path_compare_filename_one(".", "././.", -1);
        test_path_compare_filename_one("./..", ".", 1);
        test_path_compare_filename_one("x/.y", "x/y", -1);
        test_path_compare_filename_one("foo", "/foo", /* expected= */ 0);
        test_path_compare_filename_one("/foo", "/foo/bar", 1);
        test_path_compare_filename_one("/foo/aaa", "/foo/b", -1);
        test_path_compare_filename_one("/foo/aaa", "/foo/b/a", 1);
        test_path_compare_filename_one("/foo/a", "/foo/aaa", -1);
        test_path_compare_filename_one("/foo/a/b", "/foo/aaa", 1);
        test_path_compare_filename_one("/a/c", "/b/c", /* expected= */ 0);
        test_path_compare_filename_one("/a", "/a", /* expected= */ 0);
        test_path_compare_filename_one("/a/b", "/a/c", -1);
        test_path_compare_filename_one("/b", "/c", -1);
}

TEST(path_equal_root) {
        /* Nail down the details of how path_equal("/", ...) works. */

        ASSERT_PATH_EQ("/", "/");
        ASSERT_PATH_EQ("/", "//");

        ASSERT_PATH_EQ("/", "/./");
        ASSERT_FALSE(path_equal("/", "/../"));

        ASSERT_FALSE(path_equal("/", "/.../"));

        /* Make sure that files_same works as expected. */

        ASSERT_OK_POSITIVE(inode_same("/", "/", /* flags= */ 0));
        ASSERT_OK_POSITIVE(inode_same("/", "/", AT_SYMLINK_NOFOLLOW));
        ASSERT_OK_POSITIVE(inode_same("/", "//", /* flags= */ 0));
        ASSERT_OK_POSITIVE(inode_same("/", "//", AT_SYMLINK_NOFOLLOW));

        ASSERT_OK_POSITIVE(inode_same("/", "/./", /* flags= */ 0));
        ASSERT_OK_POSITIVE(inode_same("/", "/./", AT_SYMLINK_NOFOLLOW));
        ASSERT_OK_POSITIVE(inode_same("/", "/../", /* flags= */ 0));
        ASSERT_OK_POSITIVE(inode_same("/", "/../", AT_SYMLINK_NOFOLLOW));

        ASSERT_ERROR(inode_same("/", "/.../", /* flags= */ 0), ENOENT);
        ASSERT_ERROR(inode_same("/", "/.../", AT_SYMLINK_NOFOLLOW), ENOENT);

        /* The same for path_equal_or_files_same. */

        ASSERT_TRUE(path_equal_or_inode_same("/", "/", /* flags= */ 0));
        ASSERT_TRUE(path_equal_or_inode_same("/", "/", AT_SYMLINK_NOFOLLOW));
        ASSERT_TRUE(path_equal_or_inode_same("/", "//", /* flags= */ 0));
        ASSERT_TRUE(path_equal_or_inode_same("/", "//", AT_SYMLINK_NOFOLLOW));

        ASSERT_TRUE(path_equal_or_inode_same("/", "/./", /* flags= */ 0));
        ASSERT_TRUE(path_equal_or_inode_same("/", "/./", AT_SYMLINK_NOFOLLOW));
        ASSERT_TRUE(path_equal_or_inode_same("/", "/../", /* flags= */ 0));
        ASSERT_TRUE(path_equal_or_inode_same("/", "/../", AT_SYMLINK_NOFOLLOW));

        ASSERT_FALSE(path_equal_or_inode_same("/", "/.../", /* flags= */ 0));
        ASSERT_FALSE(path_equal_or_inode_same("/", "/.../", AT_SYMLINK_NOFOLLOW));
}

TEST(find_executable_full) {
        char *p, *bp;
        _cleanup_free_ char *test_file_name = NULL;
        _cleanup_close_ int fd = -EBADF;
        char fn[] = "/tmp/test-XXXXXX";

        ASSERT_OK_ZERO(find_executable_full("sh", /* root= */ NULL, /* exec_search_path= */ NULL, /* use_path_envvar= */ true, &p, /* ret_fd= */ NULL));
        puts(p);
        ASSERT_OK(path_extract_filename(p, &bp));
        ASSERT_STREQ(bp, "sh");
        free(p);
        free(bp);

        ASSERT_OK_ZERO(find_executable_full("sh", /* root= */ NULL, /* exec_search_path= */ NULL, /* use_path_envvar= */ false, &p, /* ret_fd= */ NULL));
        puts(p);
        ASSERT_OK(path_extract_filename(p, &bp));
        ASSERT_STREQ(bp, "sh");
        free(p);
        free(bp);

        _cleanup_free_ char *oldpath = NULL;
        p = getenv("PATH");
        if (p)
                ASSERT_NOT_NULL(oldpath = strdup(p));

        ASSERT_OK_ZERO_ERRNO(unsetenv("PATH"));

        ASSERT_OK_ZERO(find_executable_full("sh", /* root= */ NULL, /* exec_search_path= */ NULL, /* use_path_envvar= */ true, &p, /* ret_fd= */ NULL));
        puts(p);
        ASSERT_OK(path_extract_filename(p, &bp));
        ASSERT_STREQ(bp, "sh");
        free(p);
        free(bp);

        ASSERT_OK_ZERO(find_executable_full("sh", /* root= */ NULL, /* exec_search_path= */ NULL, /* use_path_envvar= */ false, &p, /* ret_fd= */ NULL));
        puts(p);
        ASSERT_OK(path_extract_filename(p, &bp));
        ASSERT_STREQ(bp, "sh");
        free(p);
        free(bp);

        if (oldpath)
                ASSERT_OK_ERRNO(setenv("PATH", oldpath, true));

        ASSERT_OK(fd = mkostemp_safe(fn));
        ASSERT_OK_ERRNO(fchmod(fd, 0755));

        ASSERT_OK(path_extract_filename(fn, &test_file_name));

        ASSERT_OK_ZERO(find_executable_full(test_file_name, /* root= */ NULL, STRV_MAKE("/doesnotexist", "/tmp", "/bin"), /* use_path_envvar= */ false, &p, /* ret_fd= */ NULL));
        puts(p);
        ASSERT_STREQ(p, fn);
        free(p);

        (void) unlink(fn);
        ASSERT_ERROR(find_executable_full(test_file_name, /* root= */ NULL, STRV_MAKE("/doesnotexist", "/tmp", "/bin"), /* use_path_envvar= */ false, &p, /* ret_fd= */ NULL), ENOENT);
}

TEST(find_executable) {
        char *p;
        _cleanup_free_ char *bp = NULL;

        ASSERT_OK_ZERO(find_executable("/bin/sh", &p));
        puts(p);
        ASSERT_PATH_EQ(p, "/bin/sh");
        free(p);

        ASSERT_OK_ZERO(find_executable(saved_argv[0], &p));
        puts(p);
        ASSERT_NOT_NULL(endswith(p, "/test-path-util"));
        ASSERT_TRUE(path_is_absolute(p));
        free(p);

        ASSERT_OK_ZERO(find_executable("sh", &p));
        puts(p);
        ASSERT_NOT_NULL(endswith(p, "/sh"));
        ASSERT_TRUE(path_is_absolute(p));
        free(p);

        ASSERT_OK_ZERO(find_executable("/bin/touch", &p));
        ASSERT_STREQ(p, "/bin/touch");
        free(p);

        ASSERT_OK_ZERO(find_executable("touch", &p));
        ASSERT_TRUE(path_is_absolute(p));
        ASSERT_OK(path_extract_filename(p, &bp));
        ASSERT_STREQ(bp, "touch");
        free(p);

        ASSERT_ERROR(find_executable("xxxx-xxxx", &p), ENOENT);
        ASSERT_ERROR(find_executable("/some/dir/xxxx-xxxx", &p), ENOENT);
        ASSERT_ERROR(find_executable("/proc/filesystems", &p), EACCES);
}

static void test_find_executable_exec_one(const char *path) {
        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        r = find_executable_full(path, /* root= */ NULL, /* exec_search_path= */ NULL, /* use_path_envvar= */ false, &t, &fd);

        log_info_errno(r, "%s: %s → %s: %d/%m", __func__, path, t ?: "-", fd);

        ASSERT_GT(fd, STDERR_FILENO);
        ASSERT_TRUE(path_is_absolute(t));
        if (path_is_absolute(path))
                ASSERT_STREQ(t, path);

        r = ASSERT_OK(pidref_safe_fork(
                        "(find-exec)",
                        FORK_LOG|FORK_DEATHSIG_SIGKILL|FORK_WAIT,
                        /* ret= */ NULL));

        if (r == 0) {
                r = fexecve_or_execve(fd, t, STRV_MAKE(t, "--version"), STRV_MAKE(NULL));
                log_error_errno(r, "[f]execve: %m");
                _exit(EXIT_FAILURE);
        }
}

TEST(find_executable_exec) {
        test_find_executable_exec_one("touch");
        test_find_executable_exec_one("/bin/touch");

        _cleanup_free_ char *script = NULL;
        ASSERT_OK(get_testdata_dir("test-path-util/script.sh", &script));
        test_find_executable_exec_one(script);
}

TEST(prefixes) {
        static const char* const values[] = {
                "/a/b/c/d",
                "/a/b/c",
                "/a/b",
                "/a",
                "",
                NULL
        };
        unsigned i;
        char s[PATH_MAX];
        bool b;

        i = 0;
        PATH_FOREACH_PREFIX_MORE(s, "/a/b/c/d") {
                log_error("---%s---", s);
                ASSERT_STREQ(s, values[i++]);
        }
        ASSERT_NULL(values[i]);

        i = 1;
        PATH_FOREACH_PREFIX(s, "/a/b/c/d") {
                log_error("---%s---", s);
                ASSERT_STREQ(s, values[i++]);
        }
        ASSERT_NULL(values[i]);

        i = 0;
        PATH_FOREACH_PREFIX_MORE(s, "////a////b////c///d///////")
                ASSERT_STREQ(s, values[i++]);
        ASSERT_NULL(values[i]);

        i = 1;
        PATH_FOREACH_PREFIX(s, "////a////b////c///d///////")
                ASSERT_STREQ(s, values[i++]);
        ASSERT_NULL(values[i]);

        PATH_FOREACH_PREFIX(s, "////")
                assert_not_reached();

        b = false;
        PATH_FOREACH_PREFIX_MORE(s, "////") {
                ASSERT_FALSE(b);
                ASSERT_STREQ(s, "");
                b = true;
        }
        ASSERT_TRUE(b);

        PATH_FOREACH_PREFIX(s, "")
                assert_not_reached();

        b = false;
        PATH_FOREACH_PREFIX_MORE(s, "") {
                ASSERT_FALSE(b);
                ASSERT_STREQ(s, "");
                b = true;
        }
}

TEST(path_join) {
#define test_join(expected, ...) {        \
                _cleanup_free_ char *z = NULL;   \
                z = path_join(__VA_ARGS__); \
                log_debug("got \"%s\", expected \"%s\"", z, expected); \
                ASSERT_STREQ(z, expected);   \
        }

        test_join("/root/a/b/c", "/root", "/a/b", "/c");
        test_join("/root/a/b/c", "/root", "a/b", "c");
        test_join("/root/a/b/c", "/root", "/a/b", "c");
        test_join("/root/c",     "/root", "/", "c");
        test_join("/root/",      "/root", "/", NULL);

        test_join("/a/b/c", "", "/a/b", "/c");
        test_join("a/b/c",  "", "a/b", "c");
        test_join("/a/b/c", "", "/a/b", "c");
        test_join("/c",     "", "/", "c");
        test_join("/",      "", "/", NULL);

        test_join("/a/b/c", NULL, "/a/b", "/c");
        test_join("a/b/c",  NULL, "a/b", "c");
        test_join("/a/b/c", NULL, "/a/b", "c");
        test_join("/c",     NULL, "/", "c");
        test_join("/",      NULL, "/", NULL);

        test_join("", "", NULL);
        test_join("", NULL, "");
        test_join("", NULL, NULL);

        test_join("foo/bar", "foo", "bar");
        test_join("foo/bar", "", "foo", "bar");
        test_join("foo/bar", NULL, "foo", NULL, "bar");
        test_join("foo/bar", "", "foo", "", "bar", "");
        test_join("foo/bar", "", "", "", "", "foo", "", "", "", "bar", "", "", "");

        test_join("//foo///bar//",         "", "/", "", "/foo/", "", "/", "", "/bar/", "", "/", "");
        test_join("/foo/bar/",             "/", "foo", "/", "bar", "/");
        test_join("foo/bar/baz",           "foo", "bar", "baz");
        test_join("foo/bar/baz",           "foo/", "bar", "/baz");
        test_join("foo//bar//baz",         "foo/", "/bar/", "/baz");
        test_join("//foo////bar////baz//", "//foo/", "///bar/", "///baz//");
}

TEST(path_extend) {
        _cleanup_free_ char *p = NULL;

        ASSERT_PTR_EQ(path_extend(&p, "foo", "bar", "baz"), p);
        ASSERT_STREQ(p, "foo/bar/baz");

        ASSERT_PTR_EQ(path_extend(&p, "foo", "bar", "baz"), p);
        ASSERT_STREQ(p, "foo/bar/baz/foo/bar/baz");

        p = mfree(p);
        ASSERT_PTR_EQ(path_extend(&p, "foo"), p);
        ASSERT_STREQ(p, "foo");

        ASSERT_PTR_EQ(path_extend(&p, "/foo"), p);
        ASSERT_STREQ(p, "foo/foo");
        ASSERT_PTR_EQ(path_extend(&p, "/waaaah/wahhh//"), p);
        ASSERT_STREQ(p, "foo/foo/waaaah/wahhh//"); /* path_extend() does not drop redundant slashes */
        ASSERT_PTR_EQ(path_extend(&p, "/aaa/bbb/"), p);
        ASSERT_STREQ(p, "foo/foo/waaaah/wahhh///aaa/bbb/"); /* but not add an extra slash */

        ASSERT_OK(free_and_strdup(&p, "/"));
        ASSERT_PTR_EQ(path_extend(&p, "foo"), p);
        ASSERT_STREQ(p, "/foo");
}

TEST(fsck_exists) {
        /* Ensure we use a sane default for PATH. */
        ASSERT_OK_ZERO_ERRNO(unsetenv("PATH"));

        /* We might or might not find one of these, so keep the test lax. */
        ASSERT_OK(fsck_exists_for_fstype("minix"));

        ASSERT_OK_ZERO(fsck_exists_for_fstype("AbCdE"));
        ASSERT_OK_ZERO(fsck_exists_for_fstype("/../bin/"));
}

static void test_path_make_relative_one(const char *from, const char *to, const char *expected) {
        _cleanup_free_ char *z = NULL;
        int r;

        log_info("/* %s(%s, %s) */", __func__, from, to);

        r = path_make_relative(from, to, &z);
        ASSERT_EQ(r >= 0, !!expected);
        ASSERT_STREQ(z, expected);
}

TEST(path_make_relative) {
        test_path_make_relative_one("some/relative/path", "/some/path", /* expected= */ NULL);
        test_path_make_relative_one("/some/path", "some/relative/path", /* expected= */ NULL);
        test_path_make_relative_one("/some/dotdot/../path", "/some/path", /* expected= */ NULL);

        test_path_make_relative_one("/", "/", ".");
        test_path_make_relative_one("/", "/some/path", "some/path");
        test_path_make_relative_one("/some/path", "/some/path", ".");
        test_path_make_relative_one("/some/path", "/some/path/in/subdir", "in/subdir");
        test_path_make_relative_one("/some/path", "/", "../..");
        test_path_make_relative_one("/some/path", "/some/other/path", "../other/path");
        test_path_make_relative_one("/some/path/./dot", "/some/further/path", "../../further/path");
        test_path_make_relative_one("//extra.//.//./.slashes//./won't////fo.ol///anybody//", "/././/extra././/.slashes////ar.e/.just/././.fine///", "../../../ar.e/.just/.fine");
}

static void test_path_make_relative_parent_one(const char *from, const char *to, const char *expected) {
        _cleanup_free_ char *z = NULL;
        int r;

        log_info("/* %s(%s, %s) */", __func__, from, to);

        r = path_make_relative_parent(from, to, &z);
        ASSERT_EQ(r >= 0, !!expected);
        ASSERT_STREQ(z, expected);
}

TEST(path_make_relative_parent) {
        test_path_make_relative_parent_one("some/relative/path/hoge", "/some/path", /* expected= */ NULL);
        test_path_make_relative_parent_one("/some/path/hoge", "some/relative/path", /* expected= */ NULL);
        test_path_make_relative_parent_one("/some/dotdot/../path/hoge", "/some/path", /* expected= */ NULL);
        test_path_make_relative_parent_one("/", "/aaa", /* expected= */ NULL);

        test_path_make_relative_parent_one("/hoge", "/", ".");
        test_path_make_relative_parent_one("/hoge", "/some/path", "some/path");
        test_path_make_relative_parent_one("/some/path/hoge", "/some/path", ".");
        test_path_make_relative_parent_one("/some/path/hoge", "/some/path/in/subdir", "in/subdir");
        test_path_make_relative_parent_one("/some/path/hoge", "/", "../..");
        test_path_make_relative_parent_one("/some/path/hoge", "/some/other/path", "../other/path");
        test_path_make_relative_parent_one("/some/path/./dot/hoge", "/some/further/path", "../../further/path");
        test_path_make_relative_parent_one("//extra.//.//./.slashes//./won't////fo.ol///anybody//hoge", "/././/extra././/.slashes////ar.e/.just/././.fine///", "../../../ar.e/.just/.fine");
}

TEST(path_strv_resolve) {
        char tmp_dir[] = "/tmp/test-path-util-XXXXXX";
        _cleanup_strv_free_ char **search_dirs = NULL;
        _cleanup_strv_free_ char **absolute_dirs = NULL;

        ASSERT_NOT_NULL(mkdtemp(tmp_dir));

        search_dirs = ASSERT_NOT_NULL(strv_new("/dir1", "/dir2", "/dir3"));
        STRV_FOREACH(d, search_dirs) {
                char *p = ASSERT_NOT_NULL(path_join(tmp_dir, *d));
                ASSERT_OK_ZERO(strv_push(&absolute_dirs, p));
        }

        ASSERT_OK_ZERO_ERRNO(mkdir(absolute_dirs[0], 0700));
        ASSERT_OK_ZERO_ERRNO(mkdir(absolute_dirs[1], 0700));
        ASSERT_OK_ZERO_ERRNO(symlink("dir2", absolute_dirs[2]));

        path_strv_resolve(search_dirs, tmp_dir);
        ASSERT_STREQ(search_dirs[0], "/dir1");
        ASSERT_STREQ(search_dirs[1], "/dir2");
        ASSERT_STREQ(search_dirs[2], "/dir2");

        ASSERT_OK_ZERO(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL));
}

static void test_path_startswith_one(const char *path, const char *prefix, const char *skipped, const char *expected) {
        const char *p, *q;

        log_debug("/* %s(%s, %s) */", __func__, path, prefix);

        p = path_startswith(path, prefix);
        ASSERT_STREQ(p, expected);
        if (p) {
                q = strjoina(skipped, p);
                ASSERT_STREQ(q, path);
                ASSERT_PTR_EQ(p, path + strlen(skipped));
        }
}

TEST(path_startswith) {
        test_path_startswith_one("/foo/bar/barfoo/", "/foo", "/foo/", "bar/barfoo/");
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/", "/foo/", "bar/barfoo/");
        test_path_startswith_one("/foo/bar/barfoo/", "/", "/", "foo/bar/barfoo/");
        test_path_startswith_one("/foo/bar/barfoo/", "////", "/",  "foo/bar/barfoo/");
        test_path_startswith_one("/foo/bar/barfoo/", "/foo//bar/////barfoo///", "/foo/bar/barfoo/", "");
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfoo////", "/foo/bar/barfoo/", "");
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar///barfoo/", "/foo/bar/barfoo/", "");
        test_path_startswith_one("/foo/bar/barfoo/", "/foo////bar/barfoo/", "/foo/bar/barfoo/", "");
        test_path_startswith_one("/foo/bar/barfoo/", "////foo/bar/barfoo/", "/foo/bar/barfoo/", "");
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfoo", "/foo/bar/barfoo/", "");

        test_path_startswith_one("/foo/./bar///barfoo/./.", "/foo", "/foo/./", "bar///barfoo/./.");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "/foo/", "/foo/./", "bar///barfoo/./.");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "/", "/", "foo/./bar///barfoo/./.");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "////", "/",  "foo/./bar///barfoo/./.");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "/foo//bar/////barfoo///", "/foo/./bar///barfoo/./.", "");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "/foo/bar/barfoo////", "/foo/./bar///barfoo/./.", "");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "/foo/bar///barfoo/", "/foo/./bar///barfoo/./.", "");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "/foo////bar/barfoo/", "/foo/./bar///barfoo/./.", "");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "////foo/bar/barfoo/", "/foo/./bar///barfoo/./.", "");
        test_path_startswith_one("/foo/./bar///barfoo/./.", "/foo/bar/barfoo", "/foo/./bar///barfoo/./.", "");

        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfooa/", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfooa", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/bar/foo", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/f/b/b/", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfo", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/bar", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/fo", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/usr/binary", "/usr/bin", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("/foo/barista", "/foo/bar", /* skipped= */ NULL, /* expected= */ NULL);
        test_path_startswith_one("foo/barista", "foo/bar", /* skipped= */ NULL, /* expected= */ NULL);
}

static void test_path_startswith_return_leading_slash_one(const char *path, const char *prefix, const char *expected) {
        const char *p;

        log_debug("/* %s(%s, %s) */", __func__, path, prefix);

        p = path_startswith_full(path, prefix, PATH_STARTSWITH_RETURN_LEADING_SLASH);
        ASSERT_STREQ(p, expected);
}

TEST(path_startswith_return_leading_slash) {
        test_path_startswith_return_leading_slash_one("/foo/bar", "/", "/foo/bar");
        test_path_startswith_return_leading_slash_one("/foo/bar", "/foo", "/bar");
        test_path_startswith_return_leading_slash_one("/foo/bar", "/foo/bar", /* expected= */ NULL);
        test_path_startswith_return_leading_slash_one("/foo/bar/", "/foo/bar", "/");
}

static void test_prefix_root_one(const char *r, const char *p, const char *expected) {
        _cleanup_free_ char *s = NULL;

        ASSERT_NOT_NULL(s = path_join(r, p));
        ASSERT_PATH_EQ(s, expected);

        _cleanup_free_ char *t = ASSERT_NOT_NULL(path_join(r, p));
        ASSERT_PATH_EQ(t, expected);
}

TEST(prefix_root) {
        test_prefix_root_one("/", "/foo", "/foo");
        test_prefix_root_one(NULL, "/foo", "/foo");
        test_prefix_root_one("", "/foo", "/foo");
        test_prefix_root_one("///", "/foo", "/foo");
        test_prefix_root_one("/", "////foo", "/foo");
        test_prefix_root_one(NULL, "////foo", "/foo");
        test_prefix_root_one("/", "foo", "/foo");
        test_prefix_root_one("", "foo", "foo");
        test_prefix_root_one(NULL, "foo", "foo");

        test_prefix_root_one("/foo", "/bar", "/foo/bar");
        test_prefix_root_one("/foo", "bar", "/foo/bar");
        test_prefix_root_one("foo", "bar", "foo/bar");
        test_prefix_root_one("/foo/", "/bar", "/foo/bar");
        test_prefix_root_one("/foo/", "//bar", "/foo/bar");
        test_prefix_root_one("/foo///", "//bar", "/foo/bar");
}

TEST(file_in_same_dir) {
        char *t;

        ASSERT_ERROR(file_in_same_dir("/", "a", &t), EADDRNOTAVAIL);

        ASSERT_OK(file_in_same_dir("/", "/a", &t));
        ASSERT_STREQ(t, "/a");
        free(t);

        ASSERT_ERROR(file_in_same_dir("", "a", &t), EINVAL);

        ASSERT_OK(file_in_same_dir("a/", "x", &t));
        ASSERT_STREQ(t, "x");
        free(t);

        ASSERT_OK(file_in_same_dir("bar/foo", "bar", &t));
        ASSERT_STREQ(t, "bar/bar");
        free(t);
}

static void test_path_find_first_component_one(
                const char *path,
                bool accept_dot_dot,
                char **expected,
                int ret) {

        log_debug("/* %s(\"%s\", accept_dot_dot=%s) */", __func__, strnull(path), yes_no(accept_dot_dot));

        for (const char *p = path;;) {
                const char *e;
                int r;

                r = path_find_first_component(&p, accept_dot_dot, &e);
                if (r <= 0) {
                        if (r == 0) {
                                if (path) {
                                        ASSERT_PTR_EQ(p, path + strlen_ptr(path));
                                        ASSERT_STREQ(p, "");
                                } else
                                        ASSERT_NULL(p);
                                ASSERT_NULL(e);
                        }
                        ASSERT_EQ(r, ret);
                        ASSERT_TRUE(strv_isempty(expected));
                        return;
                }

                ASSERT_NOT_NULL(e);
                ASSERT_EQ(strcspn(e, "/"), (size_t) r);
                ASSERT_EQ(strlen_ptr(*expected), (size_t) r);
                ASSERT_STRNEQ(e, *expected++, r);

                ASSERT_NOT_NULL(p);
                log_debug("p=%s", p);
                if (!isempty(*expected))
                        ASSERT_NOT_NULL(startswith(p, *expected));
                else if (ret >= 0) {
                        ASSERT_PTR_EQ(p, path + strlen_ptr(path));
                        ASSERT_STREQ(p, "");
                }
        }
}

TEST(path_find_first_component) {
        _cleanup_free_ char *hoge = NULL;
        char foo[NAME_MAX * 2];

        test_path_find_first_component_one(/* path= */ NULL, /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("/", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one(".", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("./", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("./.", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("..", /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_first_component_one("/..", /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_first_component_one("./..", /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_first_component_one("////./././//.", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("a/b/c", /* accept_dot_dot= */ false, STRV_MAKE("a", "b", "c"), /* ret= */ 0);
        test_path_find_first_component_one("././//.///aa/bbb//./ccc", /* accept_dot_dot= */ false, STRV_MAKE("aa", "bbb", "ccc"), /* ret= */ 0);
        test_path_find_first_component_one("././//.///aa/.../../bbb//./ccc/.", /* accept_dot_dot= */ false, STRV_MAKE("aa", "..."), -EINVAL);
        test_path_find_first_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", /* accept_dot_dot= */ false, STRV_MAKE("aaa", ".bbb"), -EINVAL);
        test_path_find_first_component_one("a/foo./b//././/", /* accept_dot_dot= */ false, STRV_MAKE("a", "foo.", "b"), /* ret= */ 0);

        test_path_find_first_component_one(/* path= */ NULL, /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("/", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one(".", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("./", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("./.", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("..", /* accept_dot_dot= */ true, STRV_MAKE(".."), /* ret= */ 0);
        test_path_find_first_component_one("/..", /* accept_dot_dot= */ true, STRV_MAKE(".."), /* ret= */ 0);
        test_path_find_first_component_one("./..", /* accept_dot_dot= */ true, STRV_MAKE(".."), /* ret= */ 0);
        test_path_find_first_component_one("////./././//.", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_first_component_one("a/b/c", /* accept_dot_dot= */ true, STRV_MAKE("a", "b", "c"), /* ret= */ 0);
        test_path_find_first_component_one("././//.///aa/bbb//./ccc", /* accept_dot_dot= */ true, STRV_MAKE("aa", "bbb", "ccc"), /* ret= */ 0);
        test_path_find_first_component_one("././//.///aa/.../../bbb//./ccc/.", /* accept_dot_dot= */ true, STRV_MAKE("aa", "...", "..", "bbb", "ccc"), /* ret= */ 0);
        test_path_find_first_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", /* accept_dot_dot= */ true, STRV_MAKE("aaa", ".bbb", "..", "c.", "d.dd", "..eeee"), /* ret= */ 0);
        test_path_find_first_component_one("a/foo./b//././/", /* accept_dot_dot= */ true, STRV_MAKE("a", "foo.", "b"), /* ret= */ 0);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_find_first_component_one(foo, /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_first_component_one(foo, /* accept_dot_dot= */ true, /* expected= */ NULL, -EINVAL);

        hoge = ASSERT_NOT_NULL(strjoin("a/b/c/", foo, "//d/e/.//f/"));

        test_path_find_first_component_one(hoge, /* accept_dot_dot= */ false, STRV_MAKE("a", "b", "c"), -EINVAL);
        test_path_find_first_component_one(hoge, /* accept_dot_dot= */ true, STRV_MAKE("a", "b", "c"), -EINVAL);
}

static void test_path_find_last_component_one(
                const char *path,
                bool accept_dot_dot,
                char **expected,
                int ret) {

        log_debug("/* %s(\"%s\", accept_dot_dot=%s) */", __func__, strnull(path), yes_no(accept_dot_dot));

        for (const char *next = NULL;;) {
                const char *e;
                int r;

                r = path_find_last_component(path, accept_dot_dot, &next, &e);
                if (r <= 0) {
                        if (r == 0) {
                                ASSERT_PTR_EQ(next, path);
                                ASSERT_NULL(e);
                        }
                        ASSERT_EQ(r, ret);
                        ASSERT_TRUE(strv_isempty(expected));
                        return;
                }

                ASSERT_NOT_NULL(e);
                ASSERT_EQ(strcspn(e, "/"), (size_t) r);
                ASSERT_EQ(strlen_ptr(*expected), (size_t) r);
                ASSERT_STRNEQ(e, *expected++, r);

                ASSERT_NOT_NULL(next);
                log_debug("path=%s\nnext=%s", path, next);
                if (!isempty(*expected)) {
                        ASSERT_TRUE(next < path + strlen(path));
                        ASSERT_TRUE(next >= path + strlen(*expected));
                        ASSERT_NOT_NULL(startswith(next - strlen(*expected), *expected));
                } else if (ret >= 0)
                        ASSERT_PTR_EQ(next, path);
        }
}

TEST(path_find_last_component) {
        _cleanup_free_ char *hoge = NULL;
        char foo[NAME_MAX * 2];

        test_path_find_last_component_one(/* path= */ NULL, /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("/", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one(".", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("./", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("./.", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("..", /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_last_component_one("/..", /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_last_component_one("./..", /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_last_component_one("////./././//.", /* accept_dot_dot= */ false, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("a/b/c", /* accept_dot_dot= */ false, STRV_MAKE("c", "b", "a"), /* ret= */ 0);
        test_path_find_last_component_one("././//.///aa./.bbb//./ccc/././/", /* accept_dot_dot= */ false, STRV_MAKE("ccc", ".bbb", "aa."), /* ret= */ 0);
        test_path_find_last_component_one("././//.///aa/../.../bbb//./ccc/.", /* accept_dot_dot= */ false, STRV_MAKE("ccc", "bbb", "..."), -EINVAL);
        test_path_find_last_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", /* accept_dot_dot= */ false, STRV_MAKE("..eeee", "d.dd", "c."), -EINVAL);

        test_path_find_last_component_one(/* path= */ NULL, /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("/", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one(".", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("./", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("./.", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("..", /* accept_dot_dot= */ true, STRV_MAKE(".."), /* ret= */ 0);
        test_path_find_last_component_one("/..", /* accept_dot_dot= */ true, STRV_MAKE(".."), /* ret= */ 0);
        test_path_find_last_component_one("./..", /* accept_dot_dot= */ true, STRV_MAKE(".."), /* ret= */ 0);
        test_path_find_last_component_one("////./././//.", /* accept_dot_dot= */ true, /* expected= */ NULL, /* ret= */ 0);
        test_path_find_last_component_one("a/b/c", /* accept_dot_dot= */ true, STRV_MAKE("c", "b", "a"), /* ret= */ 0);
        test_path_find_last_component_one("././//.///aa./.bbb//./ccc/././/", /* accept_dot_dot= */ true, STRV_MAKE("ccc", ".bbb", "aa."), /* ret= */ 0);
        test_path_find_last_component_one("././//.///aa/../.../bbb//./ccc/.", /* accept_dot_dot= */ true, STRV_MAKE("ccc", "bbb", "...", "..", "aa"), /* ret= */ 0);
        test_path_find_last_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", /* accept_dot_dot= */ true, STRV_MAKE("..eeee", "d.dd", "c.", "..", ".bbb", "aaa"), /* ret= */ 0);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_find_last_component_one(foo, /* accept_dot_dot= */ false, /* expected= */ NULL, -EINVAL);
        test_path_find_last_component_one(foo, /* accept_dot_dot= */ true, /* expected= */ NULL, -EINVAL);

        hoge = ASSERT_NOT_NULL(strjoin(foo, "/a/b/c/"));

        test_path_find_last_component_one(hoge, /* accept_dot_dot= */ false, STRV_MAKE("c", "b", "a"), -EINVAL);
        test_path_find_last_component_one(hoge, /* accept_dot_dot= */ true, STRV_MAKE("c", "b", "a"), -EINVAL);
}

TEST(last_path_component) {
        ASSERT_NULL(last_path_component(/* path= */ NULL));
        ASSERT_STREQ(last_path_component("a/b/c"), "c");
        ASSERT_STREQ(last_path_component("a/b/c/"), "c/");
        ASSERT_STREQ(last_path_component("/"), "/");
        ASSERT_STREQ(last_path_component("//"), "/");
        ASSERT_STREQ(last_path_component("///"), "/");
        ASSERT_STREQ(last_path_component("."), ".");
        ASSERT_STREQ(last_path_component("./."), ".");
        ASSERT_STREQ(last_path_component("././"), "./");
        ASSERT_STREQ(last_path_component("././/"), ".//");
        ASSERT_STREQ(last_path_component("/foo/a"), "a");
        ASSERT_STREQ(last_path_component("/foo/a/"), "a/");
        ASSERT_STREQ(last_path_component(""), "");
        ASSERT_STREQ(last_path_component("a"), "a");
        ASSERT_STREQ(last_path_component("a/"), "a/");
        ASSERT_STREQ(last_path_component("/a"), "a");
        ASSERT_STREQ(last_path_component("/a/"), "a/");
}

static void test_path_extract_filename_one(const char *input, const char *output, int ret) {
        _cleanup_free_ char *k = NULL, *k2 = NULL;
        int r;

        r = path_extract_filename(input, &k);
        log_info("%s → %s/%s [expected: %s/%s]",
                 strnull(input),
                 strnull(k), r < 0 ? STRERROR(r) : "-",
                 strnull(output), ret < 0 ? STRERROR(ret) : "-");
        ASSERT_STREQ(k, output);
        ASSERT_EQ(r, ret);

        /* Extra safety check: make sure that path_split_prefix_filename() behaves the same */
        r = path_split_prefix_filename(input, /* ret_dir= */ NULL, &k2);
        if (r >= 0) {
                ASSERT_STREQ(k2, k);
                ASSERT_EQ(r, ret);
        }
}

TEST(path_extract_filename) {
        test_path_extract_filename_one(/* input= */ NULL, /* output= */ NULL, -EINVAL);
        test_path_extract_filename_one("a/b/c", "c", /* ret= */ 0);
        test_path_extract_filename_one("a/b/c/", "c", O_DIRECTORY);
        test_path_extract_filename_one("/", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("//", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("///", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("/.", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one(".", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("./", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("./.", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("././", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("././/", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("/foo/a", "a", /* ret= */ 0);
        test_path_extract_filename_one("/foo/a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("", /* output= */ NULL, -EINVAL);
        test_path_extract_filename_one("a", "a", /* ret= */ 0);
        test_path_extract_filename_one("a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("a/././//.", "a", O_DIRECTORY);
        test_path_extract_filename_one("/a", "a", /* ret= */ 0);
        test_path_extract_filename_one("/a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("/a//./.", "a", O_DIRECTORY);
        test_path_extract_filename_one("/////////////a/////////////", "a", O_DIRECTORY);
        test_path_extract_filename_one("//./a/.///b./././.c//./d//.", "d", O_DIRECTORY);
        test_path_extract_filename_one("xx/.", "xx", O_DIRECTORY);
        test_path_extract_filename_one("xx/..", /* output= */ NULL, -EINVAL);
        test_path_extract_filename_one("..", /* output= */ NULL, -EINVAL);
        test_path_extract_filename_one("/..", /* output= */ NULL, -EINVAL);
        test_path_extract_filename_one("../", /* output= */ NULL, -EINVAL);
}

static void test_path_extract_directory_one(const char *input, const char *output, int ret) {
        _cleanup_free_ char *k = NULL, *k2 = NULL;
        int r;

        r = path_extract_directory(input, &k);
        log_info("%s → %s/%s [expected: %s/%s]",
                 strnull(input),
                 strnull(k), r < 0 ? STRERROR(r) : "-",
                 strnull(output), STRERROR(ret));
        ASSERT_STREQ(k, output);
        ASSERT_EQ(r, ret);

        /* Extra safety check: make sure that path_split_prefix_filename() behaves the same.
         * We can’t check the return value from it though as that differs based on the filename component.
         * We can only assert that if path_extract_directory() fails, then
         * path_split_prefix_filename() must also fail. */
        r = path_split_prefix_filename(input, &k2, /* ret_filename= */ NULL);
        ASSERT_STREQ(k2, k);
        ASSERT_TRUE(!(ret < 0) || r < 0);

        /* Extra safety check: let's make sure that if we split out the filename too (and it works) the
         * joined parts are identical to the original again */
        if (r >= 0) {
                _cleanup_free_ char *f = NULL, *k3 = NULL, *f2 = NULL;

                r = path_extract_filename(input, &f);
                if (r >= 0) {
                        _cleanup_free_ char *j = NULL;

                        ASSERT_NOT_NULL(j = path_join(k, f));
                        ASSERT_PATH_EQ(input, j);
                }

                /* And the same, but for path_split_prefix_filename() */
                r = path_split_prefix_filename(input, &k3, &f2);
                if (r >= 0) {
                        ASSERT_STREQ(k3, k);
                        ASSERT_STREQ(f2, f);
                }
        }
}

TEST(path_extract_directory) {
        test_path_extract_directory_one(/* input= */ NULL, /* output= */ NULL, -EINVAL);
        test_path_extract_directory_one("a/b/c", "a/b", /* ret= */ 0);
        test_path_extract_directory_one("a/b/c/", "a/b", /* ret= */ 0);
        test_path_extract_directory_one("/", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("//", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("///", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("/.", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one(".", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("./", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("./.", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("././", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("././/", /* output= */ NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("/foo/a", "/foo", /* ret= */ 0);
        test_path_extract_directory_one("/foo/a/", "/foo", /* ret= */ 0);
        test_path_extract_directory_one("", /* output= */ NULL, -EINVAL);
        test_path_extract_directory_one("a", /* output= */ NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("a/", /* output= */ NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("a/././//.", /* output= */ NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("/a", "/", /* ret= */ 0);
        test_path_extract_directory_one("/a/", "/", /* ret= */ 0);
        test_path_extract_directory_one("/a//./.", "/", /* ret= */ 0);
        test_path_extract_directory_one("/////////////a/////////////", "/", /* ret= */ 0);
        test_path_extract_directory_one("//./a/.///b./././.c//./d//.", "/a/b./.c", /* ret= */ 0);
        test_path_extract_directory_one("xx/.", /* output= */ NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("xx/..", /* output= */ NULL, -EINVAL);
        test_path_extract_directory_one("..", /* output= */ NULL, -EINVAL);
        test_path_extract_directory_one("/..", /* output= */ NULL, -EINVAL);
        test_path_extract_directory_one("../", /* output= */ NULL, -EINVAL);
}

TEST(filename_is_valid) {
        char foo[NAME_MAX+2];

        ASSERT_FALSE(filename_is_valid(""));
        ASSERT_FALSE(filename_is_valid("/bar/foo"));
        ASSERT_FALSE(filename_is_valid("/"));
        ASSERT_FALSE(filename_is_valid("."));
        ASSERT_FALSE(filename_is_valid(".."));
        ASSERT_FALSE(filename_is_valid("bar/foo"));
        ASSERT_FALSE(filename_is_valid("bar/foo/"));
        ASSERT_FALSE(filename_is_valid("bar//"));

        memset(foo, 'a', sizeof(foo) - 1);
        char_array_0(foo);

        ASSERT_FALSE(filename_is_valid(foo));

        ASSERT_TRUE(filename_is_valid("foo_bar-333"));
        ASSERT_TRUE(filename_is_valid("o.o"));
}

static void test_path_is_valid_and_safe_one(const char *p, bool ret) {
        log_debug("/* %s(\"%s\") */", __func__, strnull(p));

        ASSERT_EQ(path_is_valid(p), ret);
        if (ret)
                ret = !streq(p, "..") &&
                        !startswith(p, "../") &&
                        !endswith(p, "/..") &&
                        !strstr(p, "/../");
        ASSERT_EQ(path_is_safe(p), ret);
}

TEST(path_is_valid_and_safe) {
        char foo[PATH_MAX+2];
        const char *c;

        test_path_is_valid_and_safe_one("", /* ret= */ false);
        test_path_is_valid_and_safe_one("/bar/foo", /* ret= */ true);
        test_path_is_valid_and_safe_one("/bar/foo/", /* ret= */ true);
        test_path_is_valid_and_safe_one("/bar/foo/", /* ret= */ true);
        test_path_is_valid_and_safe_one("//bar//foo//", /* ret= */ true);
        test_path_is_valid_and_safe_one("/", /* ret= */ true);
        test_path_is_valid_and_safe_one("/////", /* ret= */ true);
        test_path_is_valid_and_safe_one("/////.///.////...///..//.", /* ret= */ true);
        test_path_is_valid_and_safe_one(".", /* ret= */ true);
        test_path_is_valid_and_safe_one("..", /* ret= */ true);
        test_path_is_valid_and_safe_one("bar/foo", /* ret= */ true);
        test_path_is_valid_and_safe_one("bar/foo/", /* ret= */ true);
        test_path_is_valid_and_safe_one("bar//", /* ret= */ true);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_is_valid_and_safe_one(foo, /* ret= */ false);

        c = strjoina("/xxx/", foo, "/yyy");
        test_path_is_valid_and_safe_one(c, /* ret= */ false);

        test_path_is_valid_and_safe_one("foo_bar-333", /* ret= */ true);
        test_path_is_valid_and_safe_one("o.o", /* ret= */ true);
}

TEST(hidden_or_backup_file) {
        ASSERT_TRUE(hidden_or_backup_file(".hidden"));
        ASSERT_TRUE(hidden_or_backup_file("..hidden"));
        ASSERT_FALSE(hidden_or_backup_file("hidden."));

        ASSERT_TRUE(hidden_or_backup_file("backup~"));
        ASSERT_TRUE(hidden_or_backup_file(".backup~"));

        ASSERT_TRUE(hidden_or_backup_file("lost+found"));
        ASSERT_TRUE(hidden_or_backup_file("aquota.user"));
        ASSERT_TRUE(hidden_or_backup_file("aquota.group"));

        ASSERT_TRUE(hidden_or_backup_file("test.ignore"));
        ASSERT_TRUE(hidden_or_backup_file("test.rpmnew"));
        ASSERT_TRUE(hidden_or_backup_file("test.dpkg-old"));
        ASSERT_TRUE(hidden_or_backup_file("test.dpkg-remove"));
        ASSERT_TRUE(hidden_or_backup_file("test.swp"));

        ASSERT_FALSE(hidden_or_backup_file("test.rpmnew."));
        ASSERT_FALSE(hidden_or_backup_file("test.dpkg-old.foo"));
}

TEST(skip_dev_prefix) {
        ASSERT_STREQ(skip_dev_prefix("/"), "/");
        ASSERT_STREQ(skip_dev_prefix("/dev"), "");
        ASSERT_STREQ(skip_dev_prefix("/dev/"), "");
        ASSERT_STREQ(skip_dev_prefix("/dev/foo"), "foo");
        ASSERT_STREQ(skip_dev_prefix("/dev/foo/bar"), "foo/bar");
        ASSERT_STREQ(skip_dev_prefix("//dev"), "");
        ASSERT_STREQ(skip_dev_prefix("//dev//"), "");
        ASSERT_STREQ(skip_dev_prefix("/dev///foo"), "foo");
        ASSERT_STREQ(skip_dev_prefix("///dev///foo///bar"), "foo///bar");
        ASSERT_STREQ(skip_dev_prefix("//foo"), "//foo");
        ASSERT_STREQ(skip_dev_prefix("foo"), "foo");
}

TEST(empty_or_root) {
        ASSERT_TRUE(empty_or_root(/* path= */ NULL));
        ASSERT_TRUE(empty_or_root(""));
        ASSERT_TRUE(empty_or_root("/"));
        ASSERT_TRUE(empty_or_root("//"));
        ASSERT_TRUE(empty_or_root("///"));
        ASSERT_TRUE(empty_or_root("/////////////////"));
        ASSERT_FALSE(empty_or_root("xxx"));
        ASSERT_FALSE(empty_or_root("/xxx"));
        ASSERT_FALSE(empty_or_root("/xxx/"));
        ASSERT_FALSE(empty_or_root("//yy//"));
}

TEST(empty_or_root_harder_to_null) {
        const char *p;

        p = NULL;
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_NULL(p);

        p = "/";
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_NULL(p);

        p = "////////";
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_NULL(p);

        p = "/../../././//";
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_NULL(p);

        p = "/usr";
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_STREQ(p, "/usr");

        p = "/usr/../../../";
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_NULL(p);

        p = "/usr/";
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_STREQ(p, "/usr/");

        p = "///././/../../usr////";
        ASSERT_OK(empty_or_root_harder_to_null(&p));
        ASSERT_STREQ(p, "///././/../../usr////");
}

TEST(path_startswith_set) {
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/foo/bar", "/zzz"), "");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/foo/", "/zzz"), "bar");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/foo", "/zzz"), "bar");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/", "/zzz"), "foo/bar");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "", "/zzz"), NULL);

        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/foo/bar", "/zzz"), NULL);
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/foo/", "/zzz"), "bar2");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/foo", "/zzz"), "bar2");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/", "/zzz"), "foo/bar2");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "", "/zzz"), NULL);

        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/foo/bar", "/zzz"), NULL);
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/foo/", "/zzz"), NULL);
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/foo", "/zzz"), NULL);
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/", "/zzz"), "foo2/bar");
        ASSERT_STREQ(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "", "/zzz"), NULL);
}

TEST(path_startswith_strv) {
        ASSERT_STREQ(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/foo/bar", "/zzz")), "");
        ASSERT_STREQ(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/foo/", "/zzz")), "bar");
        ASSERT_STREQ(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/foo", "/zzz")), "bar");
        ASSERT_STREQ(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/", "/zzz")), "foo/bar");
        ASSERT_STREQ(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "", "/zzz")), NULL);

        ASSERT_STREQ(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/foo/bar", "/zzz")), NULL);
        ASSERT_STREQ(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/foo/", "/zzz")), "bar2");
        ASSERT_STREQ(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/foo", "/zzz")), "bar2");
        ASSERT_STREQ(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/", "/zzz")), "foo/bar2");
        ASSERT_STREQ(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "", "/zzz")), NULL);

        ASSERT_STREQ(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/foo/bar", "/zzz")), NULL);
        ASSERT_STREQ(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/foo/", "/zzz")), NULL);
        ASSERT_STREQ(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/foo", "/zzz")), NULL);
        ASSERT_STREQ(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/", "/zzz")), "foo2/bar");
        ASSERT_STREQ(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "", "/zzz")), NULL);
}

static void test_path_glob_can_match_one(const char *pattern, const char *prefix, const char *expected) {
        _cleanup_free_ char *result = NULL;

        log_debug("%s(%s, %s, %s)", __func__, pattern, prefix, strnull(expected));

        ASSERT_OK_EQ(path_glob_can_match(pattern, prefix, &result), !!expected);
        ASSERT_STREQ(result, expected);
}

TEST(path_glob_can_match) {
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo/hoge/aaa/bbb", /* expected= */ NULL);
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo/hoge/aaa", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo/hoge", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/hoge/aaa", "/", "/foo/hoge/aaa");

        test_path_glob_can_match_one("/foo/*/aaa", "/foo/hoge/aaa/bbb", /* expected= */ NULL);
        test_path_glob_can_match_one("/foo/*/aaa", "/foo/hoge/aaa", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/*/aaa", "/foo/hoge", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/*/aaa", "/foo", "/foo/*/aaa");
        test_path_glob_can_match_one("/foo/*/aaa", "/", "/foo/*/aaa");

        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx/yyy/aaa/bbb", /* expected= */ NULL);
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx/yyy/aaa", "/foo/xxx/yyy/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx/yyy", "/foo/xxx/yyy/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx", "/foo/xxx/*/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo", "/foo/*/*/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/", "/foo/*/*/aaa");

        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx/aaa/bbb/ccc", /* expected= */ NULL);
        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx/aaa/bbb", "/foo/xxx/aaa/bbb");
        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx/ccc", /* expected= */ NULL);
        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx/aaa", "/foo/xxx/aaa/*");
        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx", "/foo/xxx/aaa/*");
        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo", "/foo/*/aaa/*");
        test_path_glob_can_match_one("/foo/*/aaa/*", "/", "/foo/*/aaa/*");
}

TEST(print_MAX) {
        log_info("PATH_MAX=%zu\n"
                 "FILENAME_MAX=%zu\n"
                 "NAME_MAX=%zu",
                 (size_t) PATH_MAX,
                 (size_t) FILENAME_MAX,
                 (size_t) NAME_MAX);

        assert_cc(FILENAME_MAX == PATH_MAX);
}

TEST(path_implies_directory) {
        ASSERT_FALSE(path_implies_directory(/* path= */ NULL));
        ASSERT_FALSE(path_implies_directory(""));
        ASSERT_TRUE(path_implies_directory("/"));
        ASSERT_TRUE(path_implies_directory("////"));
        ASSERT_TRUE(path_implies_directory("////.///"));
        ASSERT_TRUE(path_implies_directory("////./"));
        ASSERT_TRUE(path_implies_directory("////."));
        ASSERT_TRUE(path_implies_directory("."));
        ASSERT_TRUE(path_implies_directory("./"));
        ASSERT_TRUE(path_implies_directory("/."));
        ASSERT_TRUE(path_implies_directory(".."));
        ASSERT_TRUE(path_implies_directory("../"));
        ASSERT_TRUE(path_implies_directory("/.."));
        ASSERT_FALSE(path_implies_directory("a"));
        ASSERT_FALSE(path_implies_directory("ab"));
        ASSERT_TRUE(path_implies_directory("ab/"));
        ASSERT_FALSE(path_implies_directory("ab/a"));
        ASSERT_TRUE(path_implies_directory("ab/a/"));
        ASSERT_TRUE(path_implies_directory("ab/a/.."));
        ASSERT_TRUE(path_implies_directory("ab/a/."));
        ASSERT_TRUE(path_implies_directory("ab/a//"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
