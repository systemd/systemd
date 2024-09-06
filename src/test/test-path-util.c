/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
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
        assert_se( path_is_absolute("/"));
        assert_se(!path_is_absolute("./"));

        ASSERT_STREQ(basename("./aa/bb/../file.da."), "file.da.");
        ASSERT_STREQ(basename("/aa///.file"), ".file");
        ASSERT_STREQ(basename("/aa///file..."), "file...");
        ASSERT_STREQ(basename("file.../"), "");

        assert_se( PATH_IN_SET("/bin", "/", "/bin", "/foo"));
        assert_se( PATH_IN_SET("/bin", "/bin"));
        assert_se( PATH_IN_SET("/bin", "/foo/bar", "/bin"));
        assert_se( PATH_IN_SET("/", "/", "/", "/foo/bar"));
        assert_se(!PATH_IN_SET("/", "/abc", "/def"));

        assert_se( path_equal(NULL, NULL));
        assert_se( path_equal("/a", "/a"));
        assert_se(!path_equal("/a", "/b"));
        assert_se(!path_equal("/a", NULL));
        assert_se(!path_equal(NULL, "/a"));
        assert_se(!path_equal("a", NULL));
        assert_se(!path_equal(NULL, "a"));
}

TEST(is_path) {
        assert_se(!is_path("foo"));
        assert_se(!is_path("dos.ext"));
        assert_se( is_path("/dir"));
        assert_se( is_path("a/b"));
        assert_se( is_path("a/b.ext"));

        assert_se(!is_path("."));
        assert_se(!is_path(""));
        assert_se(!is_path(".."));

        assert_se( is_path("/dev"));
        assert_se( is_path("/./dev"));
        assert_se( is_path("/./dev/."));
        assert_se( is_path("/./dev."));
        assert_se( is_path("//dev"));
        assert_se( is_path("///dev"));
        assert_se( is_path("/dev/"));
        assert_se( is_path("///dev/"));
        assert_se( is_path("/./dev/"));
        assert_se( is_path("/../dev/"));
        assert_se( is_path("/dev/sda"));
        assert_se( is_path("/dev/sda5"));
        assert_se( is_path("/dev/sda5b3"));
        assert_se( is_path("/dev/sda5b3/idontexit"));
        assert_se( is_path("/../dev/sda"));
        assert_se( is_path("/../../dev/sda5"));
        assert_se( is_path("/../../../dev/sda5b3"));
        assert_se( is_path("/.././.././dev/sda5b3/idontexit"));
        assert_se( is_path("/sys"));
        assert_se( is_path("/sys/"));
        assert_se( is_path("/./sys"));
        assert_se( is_path("/./sys/."));
        assert_se( is_path("/./sys."));
        assert_se( is_path("/sys/what"));
        assert_se( is_path("/sys/something/.."));
        assert_se( is_path("/sys/something/../"));
        assert_se( is_path("/sys////"));
        assert_se( is_path("/sys////."));
        assert_se( is_path("/sys/.."));
        assert_se( is_path("/sys/../"));
        assert_se( is_path("/usr/../dev/sda"));
}

TEST(is_device_path) {
        assert_se(!is_device_path("foo"));
        assert_se(!is_device_path("dos.ext"));
        assert_se(!is_device_path("/dir"));
        assert_se(!is_device_path("a/b"));
        assert_se(!is_device_path("a/b.ext"));

        assert_se(!is_device_path("."));
        assert_se(!is_device_path(""));
        assert_se(!is_device_path(".."));

        assert_se(!is_device_path("/dev"));
        assert_se(!is_device_path("/./dev"));
        assert_se(!is_device_path("/./dev/."));
        assert_se(!is_device_path("/./dev."));
        assert_se( is_device_path("/./dev/foo"));
        assert_se( is_device_path("/./dev/./foo"));
        assert_se(!is_device_path("/./dev./foo"));
        assert_se(!is_device_path("//dev"));
        assert_se(!is_device_path("///dev"));
        assert_se(!is_device_path("/dev/"));
        assert_se(!is_device_path("///dev/"));
        assert_se(!is_device_path("/./dev/"));
        assert_se(!is_device_path("/../dev/"));
        assert_se( is_device_path("/dev/sda"));
        assert_se( is_device_path("/dev/sda5"));
        assert_se( is_device_path("/dev/sda5b3"));
        assert_se( is_device_path("/dev/sda5b3/idontexit"));
        assert_se(!is_device_path("/../dev/sda"));
        assert_se(!is_device_path("/../../dev/sda5"));
        assert_se(!is_device_path("/../../../dev/sda5b3"));
        assert_se(!is_device_path("/.././.././dev/sda5b3/idontexit"));
        assert_se(!is_device_path("/sys"));
        assert_se(!is_device_path("/sys/"));
        assert_se(!is_device_path("/./sys"));
        assert_se(!is_device_path("/./sys/."));
        assert_se(!is_device_path("/./sys."));
        assert_se( is_device_path("/./sys/foo"));
        assert_se( is_device_path("/./sys/./foo"));
        assert_se(!is_device_path("/./sys./foo"));
        assert_se( is_device_path("/sys/what"));
        assert_se( is_device_path("/sys/something/.."));
        assert_se( is_device_path("/sys/something/../"));
        assert_se(!is_device_path("/sys////"));
        assert_se(!is_device_path("/sys////."));
        assert_se( is_device_path("/sys/.."));
        assert_se( is_device_path("/sys/../"));
        assert_se(!is_device_path("/usr/../dev/sda"));
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

        test_path_simplify_one("", "", 0);
        test_path_simplify_one("aaa/bbb////ccc", "aaa/bbb/ccc", 0);
        test_path_simplify_one("//aaa/.////ccc", "/aaa/ccc", 0);
        test_path_simplify_one("///", "/", 0);
        test_path_simplify_one("///", "/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("///.//", "/", 0);
        test_path_simplify_one("///.//.///", "/", 0);
        test_path_simplify_one("////.././///../.", "/", 0);
        test_path_simplify_one(".", ".", 0);
        test_path_simplify_one("./", ".", 0);
        test_path_simplify_one("./", "./", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one(".///.//./.", ".", 0);
        test_path_simplify_one(".///.//././/", ".", 0);
        test_path_simplify_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.",
                               "/aaa/.bbb/../c./d.dd/..eeee", 0);
        test_path_simplify_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                               "/aaa/.bbb/../c./d.dd/..eeee/..", 0);
        test_path_simplify_one(".//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                               "aaa/.bbb/../c./d.dd/..eeee/..", 0);
        test_path_simplify_one("..//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                               "../aaa/.bbb/../c./d.dd/..eeee/..", 0);
        test_path_simplify_one("abc///", "abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);

        test_path_simplify_one("/../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///", "/abc", 0);
        test_path_simplify_one("/../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///..", "/abc/..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///../", "/abc/../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../abc///../", "/abc/..", 0);

        test_path_simplify_one("/../../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///", "/abc", 0);
        test_path_simplify_one("/../../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///../..", "/abc/../..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///../../", "/abc/../../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/../../abc///../../", "/abc/../..", 0);

        test_path_simplify_one("/.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///", "/abc", 0);
        test_path_simplify_one("/.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///../..", "/abc/../..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///../../", "/abc/../../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.././../abc///../../", "/abc/../..", 0);

        test_path_simplify_one("/./.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///", "/abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///", "/abc", 0);
        test_path_simplify_one("/./.././../abc", "/abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///../..", "/abc/../..", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///../../", "/abc/../../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/./.././../abc///../../", "/abc/../..", 0);

        test_path_simplify_one("/.../abc", "/.../abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///", "/.../abc/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///", "/.../abc", 0);
        test_path_simplify_one("/.../abc", "/.../abc", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///...", "/.../abc/...", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///.../", "/.../abc/.../", PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
        test_path_simplify_one("/.../abc///.../", "/.../abc/...", 0);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_simplify_one(foo, foo, 0);

        hoge = strjoin("/", foo);
        assert_se(hoge);
        test_path_simplify_one(hoge, hoge, 0);
        hoge = mfree(hoge);

        hoge = strjoin("a////.//././//./b///././/./c/////././//./", foo, "//.//////d/e/.//f/");
        assert_se(hoge);

        hoge_out = strjoin("a/b/c/", foo, "//.//////d/e/.//f/");
        assert_se(hoge_out);

        test_path_simplify_one(hoge, hoge_out, 0);
}

static void test_path_compare_one(const char *a, const char *b, int expected) {
        int r;

        assert_se(path_compare(a, a) == 0);
        assert_se(path_compare(b, b) == 0);

        r = path_compare(a, b);
        assert_se((r > 0) == (expected > 0) && (r < 0) == (expected < 0));
        r = path_compare(b, a);
        assert_se((r < 0) == (expected > 0) && (r > 0) == (expected < 0));

        assert_se(path_equal(a, a) == 1);
        assert_se(path_equal(b, b) == 1);
        assert_se(path_equal(a, b) == (expected == 0));
        assert_se(path_equal(b, a) == (expected == 0));
}

TEST(path_compare) {
        test_path_compare_one("/goo", "/goo", 0);
        test_path_compare_one("/goo", "/goo", 0);
        test_path_compare_one("//goo", "/goo", 0);
        test_path_compare_one("//goo/////", "/goo", 0);
        test_path_compare_one("goo/////", "goo", 0);
        test_path_compare_one("/goo/boo", "/goo//boo", 0);
        test_path_compare_one("//goo/boo", "/goo/boo//", 0);
        test_path_compare_one("//goo/././//./boo//././//", "/goo/boo//.", 0);
        test_path_compare_one("/.", "//.///", 0);
        test_path_compare_one("/x", "x/", 1);
        test_path_compare_one("x/", "/", -1);
        test_path_compare_one("/x/./y", "x/y", 1);
        test_path_compare_one("/x/./y", "/x/y", 0);
        test_path_compare_one("/x/./././y", "/x/y/././.", 0);
        test_path_compare_one("./x/./././y", "./x/y/././.", 0);
        test_path_compare_one(".", "./.", 0);
        test_path_compare_one(".", "././.", 0);
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

        assert_se(path_compare_filename(a, a) == 0);
        assert_se(path_compare_filename(b, b) == 0);

        r = path_compare_filename(a, b);
        assert_se((r > 0) == (expected > 0) && (r < 0) == (expected < 0));
        r = path_compare_filename(b, a);
        assert_se((r < 0) == (expected > 0) && (r > 0) == (expected < 0));

        assert_se(path_equal_filename(a, a) == 1);
        assert_se(path_equal_filename(b, b) == 1);
        assert_se(path_equal_filename(a, b) == (expected == 0));
        assert_se(path_equal_filename(b, a) == (expected == 0));
}

TEST(path_compare_filename) {
        test_path_compare_filename_one("/goo", "/goo", 0);
        test_path_compare_filename_one("/goo", "/goo", 0);
        test_path_compare_filename_one("//goo", "/goo", 0);
        test_path_compare_filename_one("//goo/////", "/goo", 0);
        test_path_compare_filename_one("goo/////", "goo", 0);
        test_path_compare_filename_one("/goo/boo", "/goo//boo", 0);
        test_path_compare_filename_one("//goo/boo", "/goo/boo//", 0);
        test_path_compare_filename_one("//goo/././//./boo//././//", "/goo/boo//.", 0);
        test_path_compare_filename_one("/.", "//.///", -1);
        test_path_compare_filename_one("/x", "x/", 0);
        test_path_compare_filename_one("x/", "/", 1);
        test_path_compare_filename_one("/x/./y", "x/y", 0);
        test_path_compare_filename_one("/x/./y", "/x/y", 0);
        test_path_compare_filename_one("/x/./././y", "/x/y/././.", 0);
        test_path_compare_filename_one("./x/./././y", "./x/y/././.", 0);
        test_path_compare_filename_one(".", "./.", -1);
        test_path_compare_filename_one(".", "././.", -1);
        test_path_compare_filename_one("./..", ".", 1);
        test_path_compare_filename_one("x/.y", "x/y", -1);
        test_path_compare_filename_one("foo", "/foo", 0);
        test_path_compare_filename_one("/foo", "/foo/bar", 1);
        test_path_compare_filename_one("/foo/aaa", "/foo/b", -1);
        test_path_compare_filename_one("/foo/aaa", "/foo/b/a", 1);
        test_path_compare_filename_one("/foo/a", "/foo/aaa", -1);
        test_path_compare_filename_one("/foo/a/b", "/foo/aaa", 1);
        test_path_compare_filename_one("/a/c", "/b/c", 0);
        test_path_compare_filename_one("/a", "/a", 0);
        test_path_compare_filename_one("/a/b", "/a/c", -1);
        test_path_compare_filename_one("/b", "/c", -1);
}

TEST(path_equal_root) {
        /* Nail down the details of how path_equal("/", ...) works. */

        assert_se(path_equal("/", "/"));
        assert_se(path_equal("/", "//"));

        assert_se(path_equal("/", "/./"));
        assert_se(!path_equal("/", "/../"));

        assert_se(!path_equal("/", "/.../"));

        /* Make sure that files_same works as expected. */

        assert_se(inode_same("/", "/", 0) > 0);
        assert_se(inode_same("/", "/", AT_SYMLINK_NOFOLLOW) > 0);
        assert_se(inode_same("/", "//", 0) > 0);
        assert_se(inode_same("/", "//", AT_SYMLINK_NOFOLLOW) > 0);

        assert_se(inode_same("/", "/./", 0) > 0);
        assert_se(inode_same("/", "/./", AT_SYMLINK_NOFOLLOW) > 0);
        assert_se(inode_same("/", "/../", 0) > 0);
        assert_se(inode_same("/", "/../", AT_SYMLINK_NOFOLLOW) > 0);

        assert_se(inode_same("/", "/.../", 0) == -ENOENT);
        assert_se(inode_same("/", "/.../", AT_SYMLINK_NOFOLLOW) == -ENOENT);

        /* The same for path_equal_or_files_same. */

        assert_se(path_equal_or_inode_same("/", "/", 0));
        assert_se(path_equal_or_inode_same("/", "/", AT_SYMLINK_NOFOLLOW));
        assert_se(path_equal_or_inode_same("/", "//", 0));
        assert_se(path_equal_or_inode_same("/", "//", AT_SYMLINK_NOFOLLOW));

        assert_se(path_equal_or_inode_same("/", "/./", 0));
        assert_se(path_equal_or_inode_same("/", "/./", AT_SYMLINK_NOFOLLOW));
        assert_se(path_equal_or_inode_same("/", "/../", 0));
        assert_se(path_equal_or_inode_same("/", "/../", AT_SYMLINK_NOFOLLOW));

        assert_se(!path_equal_or_inode_same("/", "/.../", 0));
        assert_se(!path_equal_or_inode_same("/", "/.../", AT_SYMLINK_NOFOLLOW));
}

TEST(find_executable_full) {
        char *p;
        char* test_file_name;
        _cleanup_close_ int fd = -EBADF;
        char fn[] = "/tmp/test-XXXXXX";

        assert_se(find_executable_full("sh", NULL, NULL, true, &p, NULL) == 0);
        puts(p);
        ASSERT_STREQ(basename(p), "sh");
        free(p);

        assert_se(find_executable_full("sh", NULL, NULL, false, &p, NULL) == 0);
        puts(p);
        ASSERT_STREQ(basename(p), "sh");
        free(p);

        _cleanup_free_ char *oldpath = NULL;
        p = getenv("PATH");
        if (p)
                assert_se(oldpath = strdup(p));

        assert_se(unsetenv("PATH") == 0);

        assert_se(find_executable_full("sh", NULL, NULL, true, &p, NULL) == 0);
        puts(p);
        ASSERT_STREQ(basename(p), "sh");
        free(p);

        assert_se(find_executable_full("sh", NULL, NULL, false, &p, NULL) == 0);
        puts(p);
        ASSERT_STREQ(basename(p), "sh");
        free(p);

        if (oldpath)
                assert_se(setenv("PATH", oldpath, true) >= 0);

        assert_se((fd = mkostemp_safe(fn)) >= 0);
        assert_se(fchmod(fd, 0755) >= 0);

        test_file_name = basename(fn);

        assert_se(find_executable_full(test_file_name, NULL, STRV_MAKE("/doesnotexist", "/tmp", "/bin"), false, &p, NULL) == 0);
        puts(p);
        ASSERT_STREQ(p, fn);
        free(p);

        (void) unlink(fn);
        assert_se(find_executable_full(test_file_name, NULL, STRV_MAKE("/doesnotexist", "/tmp", "/bin"), false, &p, NULL) == -ENOENT);
}

TEST(find_executable) {
        char *p;

        assert_se(find_executable("/bin/sh", &p) == 0);
        puts(p);
        assert_se(path_equal(p, "/bin/sh"));
        free(p);

        assert_se(find_executable(saved_argv[0], &p) == 0);
        puts(p);
        assert_se(endswith(p, "/test-path-util"));
        assert_se(path_is_absolute(p));
        free(p);

        assert_se(find_executable("sh", &p) == 0);
        puts(p);
        assert_se(endswith(p, "/sh"));
        assert_se(path_is_absolute(p));
        free(p);

        assert_se(find_executable("/bin/touch", &p) == 0);
        ASSERT_STREQ(p, "/bin/touch");
        free(p);

        assert_se(find_executable("touch", &p) == 0);
        assert_se(path_is_absolute(p));
        ASSERT_STREQ(basename(p), "touch");
        free(p);

        assert_se(find_executable("xxxx-xxxx", &p) == -ENOENT);
        assert_se(find_executable("/some/dir/xxxx-xxxx", &p) == -ENOENT);
        assert_se(find_executable("/proc/filesystems", &p) == -EACCES);
}

static void test_find_executable_exec_one(const char *path) {
        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        pid_t pid;
        int r;

        r = find_executable_full(path, NULL, NULL, false, &t, &fd);

        log_info_errno(r, "%s: %s → %s: %d/%m", __func__, path, t ?: "-", fd);

        assert_se(fd > STDERR_FILENO);
        assert_se(path_is_absolute(t));
        if (path_is_absolute(path))
                ASSERT_STREQ(t, path);

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                r = fexecve_or_execve(fd, t, STRV_MAKE(t, "--version"), STRV_MAKE(NULL));
                log_error_errno(r, "[f]execve: %m");
                _exit(EXIT_FAILURE);
        }

        assert_se(wait_for_terminate_and_check(t, pid, WAIT_LOG) == 0);
}

TEST(find_executable_exec) {
        test_find_executable_exec_one("touch");
        test_find_executable_exec_one("/bin/touch");

        _cleanup_free_ char *script = NULL;
        assert_se(get_testdata_dir("test-path-util/script.sh", &script) >= 0);
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
                assert_se(!b);
                ASSERT_STREQ(s, "");
                b = true;
        }
        assert_se(b);

        PATH_FOREACH_PREFIX(s, "")
                assert_not_reached();

        b = false;
        PATH_FOREACH_PREFIX_MORE(s, "") {
                assert_se(!b);
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

        assert_se(path_extend(&p, "foo", "bar", "baz") == p);
        ASSERT_STREQ(p, "foo/bar/baz");

        assert_se(path_extend(&p, "foo", "bar", "baz") == p);
        ASSERT_STREQ(p, "foo/bar/baz/foo/bar/baz");

        p = mfree(p);
        assert_se(path_extend(&p, "foo") == p);
        ASSERT_STREQ(p, "foo");

        assert_se(path_extend(&p, "/foo") == p);
        ASSERT_STREQ(p, "foo/foo");
        assert_se(path_extend(&p, "/waaaah/wahhh//") == p);
        ASSERT_STREQ(p, "foo/foo/waaaah/wahhh//"); /* path_extend() does not drop redundant slashes */
        assert_se(path_extend(&p, "/aaa/bbb/") == p);
        ASSERT_STREQ(p, "foo/foo/waaaah/wahhh///aaa/bbb/"); /* but not add an extra slash */

        assert_se(free_and_strdup(&p, "/") >= 0);
        assert_se(path_extend(&p, "foo") == p);
        ASSERT_STREQ(p, "/foo");
}

TEST(fsck_exists) {
        /* Ensure we use a sane default for PATH. */
        assert_se(unsetenv("PATH") == 0);

        /* We might or might not find one of these, so keep the test lax. */
        assert_se(fsck_exists_for_fstype("minix") >= 0);

        assert_se(fsck_exists_for_fstype("AbCdE") == 0);
        assert_se(fsck_exists_for_fstype("/../bin/") == 0);
}

static void test_path_make_relative_one(const char *from, const char *to, const char *expected) {
        _cleanup_free_ char *z = NULL;
        int r;

        log_info("/* %s(%s, %s) */", __func__, from, to);

        r = path_make_relative(from, to, &z);
        assert_se((r >= 0) == !!expected);
        ASSERT_STREQ(z, expected);
}

TEST(path_make_relative) {
        test_path_make_relative_one("some/relative/path", "/some/path", NULL);
        test_path_make_relative_one("/some/path", "some/relative/path", NULL);
        test_path_make_relative_one("/some/dotdot/../path", "/some/path", NULL);

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
        assert_se((r >= 0) == !!expected);
        ASSERT_STREQ(z, expected);
}

TEST(path_make_relative_parent) {
        test_path_make_relative_parent_one("some/relative/path/hoge", "/some/path", NULL);
        test_path_make_relative_parent_one("/some/path/hoge", "some/relative/path", NULL);
        test_path_make_relative_parent_one("/some/dotdot/../path/hoge", "/some/path", NULL);
        test_path_make_relative_parent_one("/", "/aaa", NULL);

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

        search_dirs = strv_new("/dir1", "/dir2", "/dir3");
        assert_se(search_dirs);
        STRV_FOREACH(d, search_dirs) {
                char *p = path_join(tmp_dir, *d);
                assert_se(p);
                assert_se(strv_push(&absolute_dirs, p) == 0);
        }

        assert_se(mkdir(absolute_dirs[0], 0700) == 0);
        assert_se(mkdir(absolute_dirs[1], 0700) == 0);
        assert_se(symlink("dir2", absolute_dirs[2]) == 0);

        path_strv_resolve(search_dirs, tmp_dir);
        ASSERT_STREQ(search_dirs[0], "/dir1");
        ASSERT_STREQ(search_dirs[1], "/dir2");
        ASSERT_STREQ(search_dirs[2], "/dir2");

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

static void test_path_startswith_one(const char *path, const char *prefix, const char *skipped, const char *expected) {
        const char *p, *q;

        log_debug("/* %s(%s, %s) */", __func__, path, prefix);

        p = path_startswith(path, prefix);
        ASSERT_STREQ(p, expected);
        if (p) {
                q = strjoina(skipped, p);
                ASSERT_STREQ(q, path);
                assert_se(p == path + strlen(skipped));
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

        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfooa/", NULL, NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfooa", NULL, NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "", NULL, NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/bar/foo", NULL, NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/f/b/b/", NULL, NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/barfo", NULL, NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/foo/bar/bar", NULL, NULL);
        test_path_startswith_one("/foo/bar/barfoo/", "/fo", NULL, NULL);
}

static void test_prefix_root_one(const char *r, const char *p, const char *expected) {
        _cleanup_free_ char *s = NULL;
        const char *t;

        assert_se(s = path_join(r, p));
        assert_se(path_equal(s, expected));

        t = prefix_roota(r, p);
        assert_se(t);
        assert_se(path_equal(t, expected));
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

        assert_se(file_in_same_dir("/", "a", &t) == -EADDRNOTAVAIL);

        assert_se(file_in_same_dir("/", "/a", &t) >= 0);
        ASSERT_STREQ(t, "/a");
        free(t);

        assert_se(file_in_same_dir("", "a", &t) == -EINVAL);

        assert_se(file_in_same_dir("a/", "x", &t) >= 0);
        ASSERT_STREQ(t, "x");
        free(t);

        assert_se(file_in_same_dir("bar/foo", "bar", &t) >= 0);
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
                                        assert_se(p == path + strlen_ptr(path));
                                        assert_se(isempty(p));
                                } else
                                        assert_se(!p);
                                assert_se(!e);
                        }
                        assert_se(r == ret);
                        assert_se(strv_isempty(expected));
                        return;
                }

                assert_se(e);
                assert_se(strcspn(e, "/") == (size_t) r);
                assert_se(strlen_ptr(*expected) == (size_t) r);
                assert_se(strneq(e, *expected++, r));

                assert_se(p);
                log_debug("p=%s", p);
                if (!isempty(*expected))
                        assert_se(startswith(p, *expected));
                else if (ret >= 0) {
                        assert_se(p == path + strlen_ptr(path));
                        assert_se(isempty(p));
                }
        }
}

TEST(path_find_first_component) {
        _cleanup_free_ char *hoge = NULL;
        char foo[NAME_MAX * 2];

        test_path_find_first_component_one(NULL, false, NULL, 0);
        test_path_find_first_component_one("", false, NULL, 0);
        test_path_find_first_component_one("/", false, NULL, 0);
        test_path_find_first_component_one(".", false, NULL, 0);
        test_path_find_first_component_one("./", false, NULL, 0);
        test_path_find_first_component_one("./.", false, NULL, 0);
        test_path_find_first_component_one("..", false, NULL, -EINVAL);
        test_path_find_first_component_one("/..", false, NULL, -EINVAL);
        test_path_find_first_component_one("./..", false, NULL, -EINVAL);
        test_path_find_first_component_one("////./././//.", false, NULL, 0);
        test_path_find_first_component_one("a/b/c", false, STRV_MAKE("a", "b", "c"), 0);
        test_path_find_first_component_one("././//.///aa/bbb//./ccc", false, STRV_MAKE("aa", "bbb", "ccc"), 0);
        test_path_find_first_component_one("././//.///aa/.../../bbb//./ccc/.", false, STRV_MAKE("aa", "..."), -EINVAL);
        test_path_find_first_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", false, STRV_MAKE("aaa", ".bbb"), -EINVAL);
        test_path_find_first_component_one("a/foo./b//././/", false, STRV_MAKE("a", "foo.", "b"), 0);

        test_path_find_first_component_one(NULL, true, NULL, 0);
        test_path_find_first_component_one("", true, NULL, 0);
        test_path_find_first_component_one("/", true, NULL, 0);
        test_path_find_first_component_one(".", true, NULL, 0);
        test_path_find_first_component_one("./", true, NULL, 0);
        test_path_find_first_component_one("./.", true, NULL, 0);
        test_path_find_first_component_one("..", true, STRV_MAKE(".."), 0);
        test_path_find_first_component_one("/..", true, STRV_MAKE(".."), 0);
        test_path_find_first_component_one("./..", true, STRV_MAKE(".."), 0);
        test_path_find_first_component_one("////./././//.", true, NULL, 0);
        test_path_find_first_component_one("a/b/c", true, STRV_MAKE("a", "b", "c"), 0);
        test_path_find_first_component_one("././//.///aa/bbb//./ccc", true, STRV_MAKE("aa", "bbb", "ccc"), 0);
        test_path_find_first_component_one("././//.///aa/.../../bbb//./ccc/.", true, STRV_MAKE("aa", "...", "..", "bbb", "ccc"), 0);
        test_path_find_first_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", true, STRV_MAKE("aaa", ".bbb", "..", "c.", "d.dd", "..eeee"), 0);
        test_path_find_first_component_one("a/foo./b//././/", true, STRV_MAKE("a", "foo.", "b"), 0);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_find_first_component_one(foo, false, NULL, -EINVAL);
        test_path_find_first_component_one(foo, true, NULL, -EINVAL);

        hoge = strjoin("a/b/c/", foo, "//d/e/.//f/");
        assert_se(hoge);

        test_path_find_first_component_one(hoge, false, STRV_MAKE("a", "b", "c"), -EINVAL);
        test_path_find_first_component_one(hoge, true, STRV_MAKE("a", "b", "c"), -EINVAL);
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
                                assert_se(next == path);
                                assert_se(!e);
                        }
                        assert_se(r == ret);
                        assert_se(strv_isempty(expected));
                        return;
                }

                assert_se(e);
                assert_se(strcspn(e, "/") == (size_t) r);
                assert_se(strlen_ptr(*expected) == (size_t) r);
                assert_se(strneq(e, *expected++, r));

                assert_se(next);
                log_debug("path=%s\nnext=%s", path, next);
                if (!isempty(*expected)) {
                        assert_se(next < path + strlen(path));
                        assert_se(next >= path + strlen(*expected));
                        assert_se(startswith(next - strlen(*expected), *expected));
                } else if (ret >= 0)
                        assert_se(next == path);
        }
}

TEST(path_find_last_component) {
        _cleanup_free_ char *hoge = NULL;
        char foo[NAME_MAX * 2];

        test_path_find_last_component_one(NULL, false, NULL, 0);
        test_path_find_last_component_one("", false, NULL, 0);
        test_path_find_last_component_one("/", false, NULL, 0);
        test_path_find_last_component_one(".", false, NULL, 0);
        test_path_find_last_component_one("./", false, NULL, 0);
        test_path_find_last_component_one("./.", false, NULL, 0);
        test_path_find_last_component_one("..", false, NULL, -EINVAL);
        test_path_find_last_component_one("/..", false, NULL, -EINVAL);
        test_path_find_last_component_one("./..", false, NULL, -EINVAL);
        test_path_find_last_component_one("////./././//.", false, NULL, 0);
        test_path_find_last_component_one("a/b/c", false, STRV_MAKE("c", "b", "a"), 0);
        test_path_find_last_component_one("././//.///aa./.bbb//./ccc/././/", false, STRV_MAKE("ccc", ".bbb", "aa."), 0);
        test_path_find_last_component_one("././//.///aa/../.../bbb//./ccc/.", false, STRV_MAKE("ccc", "bbb", "..."), -EINVAL);
        test_path_find_last_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", false, STRV_MAKE("..eeee", "d.dd", "c."), -EINVAL);

        test_path_find_last_component_one(NULL, true, NULL, 0);
        test_path_find_last_component_one("", true, NULL, 0);
        test_path_find_last_component_one("/", true, NULL, 0);
        test_path_find_last_component_one(".", true, NULL, 0);
        test_path_find_last_component_one("./", true, NULL, 0);
        test_path_find_last_component_one("./.", true, NULL, 0);
        test_path_find_last_component_one("..", true, STRV_MAKE(".."), 0);
        test_path_find_last_component_one("/..", true, STRV_MAKE(".."), 0);
        test_path_find_last_component_one("./..", true, STRV_MAKE(".."), 0);
        test_path_find_last_component_one("////./././//.", true, NULL, 0);
        test_path_find_last_component_one("a/b/c", true, STRV_MAKE("c", "b", "a"), 0);
        test_path_find_last_component_one("././//.///aa./.bbb//./ccc/././/", true, STRV_MAKE("ccc", ".bbb", "aa."), 0);
        test_path_find_last_component_one("././//.///aa/../.../bbb//./ccc/.", true, STRV_MAKE("ccc", "bbb", "...", "..", "aa"), 0);
        test_path_find_last_component_one("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.", true, STRV_MAKE("..eeee", "d.dd", "c.", "..", ".bbb", "aaa"), 0);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_find_last_component_one(foo, false, NULL, -EINVAL);
        test_path_find_last_component_one(foo, true, NULL, -EINVAL);

        hoge = strjoin(foo, "/a/b/c/");
        assert_se(hoge);

        test_path_find_last_component_one(hoge, false, STRV_MAKE("c", "b", "a"), -EINVAL);
        test_path_find_last_component_one(hoge, true, STRV_MAKE("c", "b", "a"), -EINVAL);
}

TEST(last_path_component) {
        ASSERT_NULL(last_path_component(NULL));
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
        _cleanup_free_ char *k = NULL;
        int r;

        r = path_extract_filename(input, &k);
        log_info("%s → %s/%s [expected: %s/%s]",
                 strnull(input),
                 strnull(k), r < 0 ? STRERROR(r) : "-",
                 strnull(output), ret < 0 ? STRERROR(ret) : "-");
        ASSERT_STREQ(k, output);
        assert_se(r == ret);
}

TEST(path_extract_filename) {
        test_path_extract_filename_one(NULL, NULL, -EINVAL);
        test_path_extract_filename_one("a/b/c", "c", 0);
        test_path_extract_filename_one("a/b/c/", "c", O_DIRECTORY);
        test_path_extract_filename_one("/", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("//", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("///", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("/.", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one(".", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("./", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("./.", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("././", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("././/", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("/foo/a", "a", 0);
        test_path_extract_filename_one("/foo/a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("", NULL, -EINVAL);
        test_path_extract_filename_one("a", "a", 0);
        test_path_extract_filename_one("a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("a/././//.", "a", O_DIRECTORY);
        test_path_extract_filename_one("/a", "a", 0);
        test_path_extract_filename_one("/a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("/a//./.", "a", O_DIRECTORY);
        test_path_extract_filename_one("/////////////a/////////////", "a", O_DIRECTORY);
        test_path_extract_filename_one("//./a/.///b./././.c//./d//.", "d", O_DIRECTORY);
        test_path_extract_filename_one("xx/.", "xx", O_DIRECTORY);
        test_path_extract_filename_one("xx/..", NULL, -EINVAL);
        test_path_extract_filename_one("..", NULL, -EINVAL);
        test_path_extract_filename_one("/..", NULL, -EINVAL);
        test_path_extract_filename_one("../", NULL, -EINVAL);
}

static void test_path_extract_directory_one(const char *input, const char *output, int ret) {
        _cleanup_free_ char *k = NULL;
        int r;

        r = path_extract_directory(input, &k);
        log_info("%s → %s/%s [expected: %s/%s]",
                 strnull(input),
                 strnull(k), r < 0 ? STRERROR(r) : "-",
                 strnull(output), STRERROR(ret));
        ASSERT_STREQ(k, output);
        assert_se(r == ret);

        /* Extra safety check: let's make sure that if we split out the filename too (and it works) the
         * joined parts are identical to the original again */
        if (r >= 0) {
                _cleanup_free_ char *f = NULL;

                r = path_extract_filename(input, &f);
                if (r >= 0) {
                        _cleanup_free_ char *j = NULL;

                        assert_se(j = path_join(k, f));
                        assert_se(path_equal(input, j));
                }
        }
}

TEST(path_extract_directory) {
        test_path_extract_directory_one(NULL, NULL, -EINVAL);
        test_path_extract_directory_one("a/b/c", "a/b", 0);
        test_path_extract_directory_one("a/b/c/", "a/b", 0);
        test_path_extract_directory_one("/", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("//", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("///", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("/.", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one(".", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("./", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("./.", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("././", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("././/", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("/foo/a", "/foo", 0);
        test_path_extract_directory_one("/foo/a/", "/foo", 0);
        test_path_extract_directory_one("", NULL, -EINVAL);
        test_path_extract_directory_one("a", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("a/", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("a/././//.", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("/a", "/", 0);
        test_path_extract_directory_one("/a/", "/", 0);
        test_path_extract_directory_one("/a//./.", "/", 0);
        test_path_extract_directory_one("/////////////a/////////////", "/", 0);
        test_path_extract_directory_one("//./a/.///b./././.c//./d//.", "/a/b./.c", 0);
        test_path_extract_directory_one("xx/.", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("xx/..", NULL, -EINVAL);
        test_path_extract_directory_one("..", NULL, -EINVAL);
        test_path_extract_directory_one("/..", NULL, -EINVAL);
        test_path_extract_directory_one("../", NULL, -EINVAL);
}

TEST(filename_is_valid) {
        char foo[NAME_MAX+2];

        assert_se(!filename_is_valid(""));
        assert_se(!filename_is_valid("/bar/foo"));
        assert_se(!filename_is_valid("/"));
        assert_se(!filename_is_valid("."));
        assert_se(!filename_is_valid(".."));
        assert_se(!filename_is_valid("bar/foo"));
        assert_se(!filename_is_valid("bar/foo/"));
        assert_se(!filename_is_valid("bar//"));

        memset(foo, 'a', sizeof(foo) - 1);
        char_array_0(foo);

        assert_se(!filename_is_valid(foo));

        assert_se(filename_is_valid("foo_bar-333"));
        assert_se(filename_is_valid("o.o"));
}

static void test_path_is_valid_and_safe_one(const char *p, bool ret) {
        log_debug("/* %s(\"%s\") */", __func__, strnull(p));

        assert_se(path_is_valid(p) == ret);
        if (ret)
                ret = !streq(p, "..") &&
                        !startswith(p, "../") &&
                        !endswith(p, "/..") &&
                        !strstr(p, "/../");
        assert_se(path_is_safe(p) == ret);
}

TEST(path_is_valid_and_safe) {
        char foo[PATH_MAX+2];
        const char *c;

        test_path_is_valid_and_safe_one("", false);
        test_path_is_valid_and_safe_one("/bar/foo", true);
        test_path_is_valid_and_safe_one("/bar/foo/", true);
        test_path_is_valid_and_safe_one("/bar/foo/", true);
        test_path_is_valid_and_safe_one("//bar//foo//", true);
        test_path_is_valid_and_safe_one("/", true);
        test_path_is_valid_and_safe_one("/////", true);
        test_path_is_valid_and_safe_one("/////.///.////...///..//.", true);
        test_path_is_valid_and_safe_one(".", true);
        test_path_is_valid_and_safe_one("..", true);
        test_path_is_valid_and_safe_one("bar/foo", true);
        test_path_is_valid_and_safe_one("bar/foo/", true);
        test_path_is_valid_and_safe_one("bar//", true);

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        test_path_is_valid_and_safe_one(foo, false);

        c = strjoina("/xxx/", foo, "/yyy");
        test_path_is_valid_and_safe_one(c, false);

        test_path_is_valid_and_safe_one("foo_bar-333", true);
        test_path_is_valid_and_safe_one("o.o", true);
}

TEST(hidden_or_backup_file) {
        assert_se(hidden_or_backup_file(".hidden"));
        assert_se(hidden_or_backup_file("..hidden"));
        assert_se(!hidden_or_backup_file("hidden."));

        assert_se(hidden_or_backup_file("backup~"));
        assert_se(hidden_or_backup_file(".backup~"));

        assert_se(hidden_or_backup_file("lost+found"));
        assert_se(hidden_or_backup_file("aquota.user"));
        assert_se(hidden_or_backup_file("aquota.group"));

        assert_se(hidden_or_backup_file("test.rpmnew"));
        assert_se(hidden_or_backup_file("test.dpkg-old"));
        assert_se(hidden_or_backup_file("test.dpkg-remove"));
        assert_se(hidden_or_backup_file("test.swp"));

        assert_se(!hidden_or_backup_file("test.rpmnew."));
        assert_se(!hidden_or_backup_file("test.dpkg-old.foo"));
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
        assert_se(empty_or_root(NULL));
        assert_se(empty_or_root(""));
        assert_se(empty_or_root("/"));
        assert_se(empty_or_root("//"));
        assert_se(empty_or_root("///"));
        assert_se(empty_or_root("/////////////////"));
        assert_se(!empty_or_root("xxx"));
        assert_se(!empty_or_root("/xxx"));
        assert_se(!empty_or_root("/xxx/"));
        assert_se(!empty_or_root("//yy//"));
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

        assert_se(path_glob_can_match(pattern, prefix, &result) == !!expected);
        ASSERT_STREQ(result, expected);
}

TEST(path_glob_can_match) {
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo/hoge/aaa/bbb", NULL);
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo/hoge/aaa", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo/hoge", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/hoge/aaa", "/foo", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/hoge/aaa", "/", "/foo/hoge/aaa");

        test_path_glob_can_match_one("/foo/*/aaa", "/foo/hoge/aaa/bbb", NULL);
        test_path_glob_can_match_one("/foo/*/aaa", "/foo/hoge/aaa", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/*/aaa", "/foo/hoge", "/foo/hoge/aaa");
        test_path_glob_can_match_one("/foo/*/aaa", "/foo", "/foo/*/aaa");
        test_path_glob_can_match_one("/foo/*/aaa", "/", "/foo/*/aaa");

        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx/yyy/aaa/bbb", NULL);
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx/yyy/aaa", "/foo/xxx/yyy/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx/yyy", "/foo/xxx/yyy/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo/xxx", "/foo/xxx/*/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/foo", "/foo/*/*/aaa");
        test_path_glob_can_match_one("/foo/*/*/aaa", "/", "/foo/*/*/aaa");

        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx/aaa/bbb/ccc", NULL);
        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx/aaa/bbb", "/foo/xxx/aaa/bbb");
        test_path_glob_can_match_one("/foo/*/aaa/*", "/foo/xxx/ccc", NULL);
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
        assert_se(!path_implies_directory(NULL));
        assert_se(!path_implies_directory(""));
        assert_se(path_implies_directory("/"));
        assert_se(path_implies_directory("////"));
        assert_se(path_implies_directory("////.///"));
        assert_se(path_implies_directory("////./"));
        assert_se(path_implies_directory("////."));
        assert_se(path_implies_directory("."));
        assert_se(path_implies_directory("./"));
        assert_se(path_implies_directory("/."));
        assert_se(path_implies_directory(".."));
        assert_se(path_implies_directory("../"));
        assert_se(path_implies_directory("/.."));
        assert_se(!path_implies_directory("a"));
        assert_se(!path_implies_directory("ab"));
        assert_se(path_implies_directory("ab/"));
        assert_se(!path_implies_directory("ab/a"));
        assert_se(path_implies_directory("ab/a/"));
        assert_se(path_implies_directory("ab/a/.."));
        assert_se(path_implies_directory("ab/a/."));
        assert_se(path_implies_directory("ab/a//"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
