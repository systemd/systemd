/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "util.h"

static void test_print_paths(void) {
        log_info("DEFAULT_PATH=%s", DEFAULT_PATH);
        log_info("DEFAULT_USER_PATH=%s", DEFAULT_USER_PATH);
}

#define test_path_compare(a, b, result) {                 \
                assert_se(path_compare(a, b) == result);  \
                assert_se(path_compare(b, a) == -result); \
                assert_se(path_equal(a, b) == !result);   \
                assert_se(path_equal(b, a) == !result);   \
        }

static void test_path_simplify(const char *in, const char *out, const char *out_dot) {
        char *p;

        log_info("/* %s */", __func__);

        p = strdupa(in);
        assert_se(streq(path_simplify(p, false), out));

        p = strdupa(in);
        assert_se(streq(path_simplify(p, true), out_dot));
}

static void test_path(void) {
        log_info("/* %s */", __func__);

        test_path_compare("/goo", "/goo", 0);
        test_path_compare("/goo", "/goo", 0);
        test_path_compare("//goo", "/goo", 0);
        test_path_compare("//goo/////", "/goo", 0);
        test_path_compare("goo/////", "goo", 0);

        test_path_compare("/goo/boo", "/goo//boo", 0);
        test_path_compare("//goo/boo", "/goo/boo//", 0);

        test_path_compare("/", "///", 0);

        test_path_compare("/x", "x/", 1);
        test_path_compare("x/", "/", -1);

        test_path_compare("/x/./y", "x/y", 1);
        test_path_compare("x/.y", "x/y", -1);

        test_path_compare("foo", "/foo", -1);
        test_path_compare("/foo", "/foo/bar", -1);
        test_path_compare("/foo/aaa", "/foo/b", -1);
        test_path_compare("/foo/aaa", "/foo/b/a", -1);
        test_path_compare("/foo/a", "/foo/aaa", -1);
        test_path_compare("/foo/a/b", "/foo/aaa", -1);

        assert_se(path_is_absolute("/"));
        assert_se(!path_is_absolute("./"));

        assert_se(is_path("/dir"));
        assert_se(is_path("a/b"));
        assert_se(!is_path("."));

        assert_se(streq(basename("./aa/bb/../file.da."), "file.da."));
        assert_se(streq(basename("/aa///.file"), ".file"));
        assert_se(streq(basename("/aa///file..."), "file..."));
        assert_se(streq(basename("file.../"), ""));

        test_path_simplify("aaa/bbb////ccc", "aaa/bbb/ccc", "aaa/bbb/ccc");
        test_path_simplify("//aaa/.////ccc", "/aaa/./ccc", "/aaa/ccc");
        test_path_simplify("///", "/", "/");
        test_path_simplify("///.//", "/.", "/");
        test_path_simplify("///.//.///", "/./.", "/");
        test_path_simplify("////.././///../.", "/.././../.", "/../..");
        test_path_simplify(".", ".", ".");
        test_path_simplify("./", ".", ".");
        test_path_simplify(".///.//./.", "./././.", ".");
        test_path_simplify(".///.//././/", "./././.", ".");
        test_path_simplify("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.",
                           "/./aaa/././.bbb/../c./d.dd/..eeee/.",
                           "/aaa/.bbb/../c./d.dd/..eeee");
        test_path_simplify("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                           "/./aaa/././.bbb/../c./d.dd/..eeee/..",
                           "/aaa/.bbb/../c./d.dd/..eeee/..");
        test_path_simplify(".//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                           "././aaa/././.bbb/../c./d.dd/..eeee/..",
                           "aaa/.bbb/../c./d.dd/..eeee/..");
        test_path_simplify("..//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                           ".././aaa/././.bbb/../c./d.dd/..eeee/..",
                           "../aaa/.bbb/../c./d.dd/..eeee/..");

        assert_se(PATH_IN_SET("/bin", "/", "/bin", "/foo"));
        assert_se(PATH_IN_SET("/bin", "/bin"));
        assert_se(PATH_IN_SET("/bin", "/foo/bar", "/bin"));
        assert_se(PATH_IN_SET("/", "/", "/", "/foo/bar"));
        assert_se(!PATH_IN_SET("/", "/abc", "/def"));

        assert_se(path_equal_ptr(NULL, NULL));
        assert_se(path_equal_ptr("/a", "/a"));
        assert_se(!path_equal_ptr("/a", "/b"));
        assert_se(!path_equal_ptr("/a", NULL));
        assert_se(!path_equal_ptr(NULL, "/a"));
}

static void test_path_equal_root(void) {
        /* Nail down the details of how path_equal("/", ...) works. */

        log_info("/* %s */", __func__);

        assert_se(path_equal("/", "/"));
        assert_se(path_equal("/", "//"));

        assert_se(!path_equal("/", "/./"));
        assert_se(!path_equal("/", "/../"));

        assert_se(!path_equal("/", "/.../"));

        /* Make sure that files_same works as expected. */

        assert_se(files_same("/", "/", 0) > 0);
        assert_se(files_same("/", "/", AT_SYMLINK_NOFOLLOW) > 0);
        assert_se(files_same("/", "//", 0) > 0);
        assert_se(files_same("/", "//", AT_SYMLINK_NOFOLLOW) > 0);

        assert_se(files_same("/", "/./", 0) > 0);
        assert_se(files_same("/", "/./", AT_SYMLINK_NOFOLLOW) > 0);
        assert_se(files_same("/", "/../", 0) > 0);
        assert_se(files_same("/", "/../", AT_SYMLINK_NOFOLLOW) > 0);

        assert_se(files_same("/", "/.../", 0) == -ENOENT);
        assert_se(files_same("/", "/.../", AT_SYMLINK_NOFOLLOW) == -ENOENT);

        /* The same for path_equal_or_files_same. */

        assert_se(path_equal_or_files_same("/", "/", 0));
        assert_se(path_equal_or_files_same("/", "/", AT_SYMLINK_NOFOLLOW));
        assert_se(path_equal_or_files_same("/", "//", 0));
        assert_se(path_equal_or_files_same("/", "//", AT_SYMLINK_NOFOLLOW));

        assert_se(path_equal_or_files_same("/", "/./", 0));
        assert_se(path_equal_or_files_same("/", "/./", AT_SYMLINK_NOFOLLOW));
        assert_se(path_equal_or_files_same("/", "/../", 0));
        assert_se(path_equal_or_files_same("/", "/../", AT_SYMLINK_NOFOLLOW));

        assert_se(!path_equal_or_files_same("/", "/.../", 0));
        assert_se(!path_equal_or_files_same("/", "/.../", AT_SYMLINK_NOFOLLOW));
}

static void test_find_executable_full(void) {
        char *p;

        log_info("/* %s */", __func__);

        assert_se(find_executable_full("sh", true, &p, NULL) == 0);
        puts(p);
        assert_se(streq(basename(p), "sh"));
        free(p);

        assert_se(find_executable_full("sh", false, &p, NULL) == 0);
        puts(p);
        assert_se(streq(basename(p), "sh"));
        free(p);

        _cleanup_free_ char *oldpath = NULL;
        p = getenv("PATH");
        if (p)
                assert_se(oldpath = strdup(p));

        assert_se(unsetenv("PATH") == 0);

        assert_se(find_executable_full("sh", true, &p, NULL) == 0);
        puts(p);
        assert_se(streq(basename(p), "sh"));
        free(p);

        assert_se(find_executable_full("sh", false, &p, NULL) == 0);
        puts(p);
        assert_se(streq(basename(p), "sh"));
        free(p);

        if (oldpath)
                assert_se(setenv("PATH", oldpath, true) >= 0);
}

static void test_find_executable(const char *self) {
        char *p;

        log_info("/* %s */", __func__);

        assert_se(find_executable("/bin/sh", &p) == 0);
        puts(p);
        assert_se(path_equal(p, "/bin/sh"));
        free(p);

        assert_se(find_executable(self, &p) == 0);
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
        assert_se(streq(p, "/bin/touch"));
        free(p);

        assert_se(find_executable("touch", &p) == 0);
        assert_se(path_is_absolute(p));
        assert_se(streq(basename(p), "touch"));
        free(p);

        assert_se(find_executable("xxxx-xxxx", &p) == -ENOENT);
        assert_se(find_executable("/some/dir/xxxx-xxxx", &p) == -ENOENT);
        assert_se(find_executable("/proc/filesystems", &p) == -EACCES);
}

static void test_find_executable_exec_one(const char *path) {
        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -1;
        pid_t pid;
        int r;

        r = find_executable_full(path, false, &t, &fd);

        log_info_errno(r, "%s: %s → %s: %d/%m", __func__, path, t ?: "-", fd);

        assert_se(fd > STDERR_FILENO);
        assert_se(path_is_absolute(t));
        if (path_is_absolute(path))
                assert_se(streq(t, path));

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                r = fexecve_or_execve(fd, t, STRV_MAKE(t, "--version"), STRV_MAKE(NULL));
                log_error_errno(r, "[f]execve: %m");
                _exit(EXIT_FAILURE);
        }

        assert_se(wait_for_terminate_and_check(t, pid, WAIT_LOG) == 0);
}

static void test_find_executable_exec(void) {
        log_info("/* %s */", __func__);

        test_find_executable_exec_one("touch");
        test_find_executable_exec_one("/bin/touch");

        _cleanup_free_ char *script = NULL;
        assert_se(get_testdata_dir("test-path-util/script.sh", &script) >= 0);
        test_find_executable_exec_one(script);
}

static void test_prefixes(void) {
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

        log_info("/* %s */", __func__);

        i = 0;
        PATH_FOREACH_PREFIX_MORE(s, "/a/b/c/d") {
                log_error("---%s---", s);
                assert_se(streq(s, values[i++]));
        }
        assert_se(values[i] == NULL);

        i = 1;
        PATH_FOREACH_PREFIX(s, "/a/b/c/d") {
                log_error("---%s---", s);
                assert_se(streq(s, values[i++]));
        }
        assert_se(values[i] == NULL);

        i = 0;
        PATH_FOREACH_PREFIX_MORE(s, "////a////b////c///d///////")
                assert_se(streq(s, values[i++]));
        assert_se(values[i] == NULL);

        i = 1;
        PATH_FOREACH_PREFIX(s, "////a////b////c///d///////")
                assert_se(streq(s, values[i++]));
        assert_se(values[i] == NULL);

        PATH_FOREACH_PREFIX(s, "////")
                assert_not_reached("Wut?");

        b = false;
        PATH_FOREACH_PREFIX_MORE(s, "////") {
                assert_se(!b);
                assert_se(streq(s, ""));
                b = true;
        }
        assert_se(b);

        PATH_FOREACH_PREFIX(s, "")
                assert_not_reached("wut?");

        b = false;
        PATH_FOREACH_PREFIX_MORE(s, "") {
                assert_se(!b);
                assert_se(streq(s, ""));
                b = true;
        }
}

static void test_path_join(void) {
        log_info("/* %s */", __func__);

#define test_join(expected, ...) {        \
                _cleanup_free_ char *z = NULL;   \
                z = path_join(__VA_ARGS__); \
                log_debug("got \"%s\", expected \"%s\"", z, expected); \
                assert_se(streq(z, expected));   \
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

static void test_fsck_exists(void) {
        log_info("/* %s */", __func__);

        /* Ensure we use a sane default for PATH. */
        assert_se(unsetenv("PATH") == 0);

        /* fsck.minix is provided by util-linux and will probably exist. */
        assert_se(fsck_exists("minix") == 1);

        assert_se(fsck_exists("AbCdE") == 0);
        assert_se(fsck_exists("/../bin/") == 0);
}

static void test_make_relative(void) {
        char *result;

        log_info("/* %s */", __func__);

        assert_se(path_make_relative("some/relative/path", "/some/path", &result) < 0);
        assert_se(path_make_relative("/some/path", "some/relative/path", &result) < 0);
        assert_se(path_make_relative("/some/dotdot/../path", "/some/path", &result) < 0);

#define test(from_dir, to_path, expected) {                \
                _cleanup_free_ char *z = NULL;             \
                path_make_relative(from_dir, to_path, &z); \
                assert_se(streq(z, expected));             \
        }

        test("/", "/", ".");
        test("/", "/some/path", "some/path");
        test("/some/path", "/some/path", ".");
        test("/some/path", "/some/path/in/subdir", "in/subdir");
        test("/some/path", "/", "../..");
        test("/some/path", "/some/other/path", "../other/path");
        test("/some/path/./dot", "/some/further/path", "../../further/path");
        test("//extra.//.//./.slashes//./won't////fo.ol///anybody//", "/././/extra././/.slashes////ar.e/.just/././.fine///", "../../../ar.e/.just/.fine");
}

static void test_strv_resolve(void) {
        char tmp_dir[] = "/tmp/test-path-util-XXXXXX";
        _cleanup_strv_free_ char **search_dirs = NULL;
        _cleanup_strv_free_ char **absolute_dirs = NULL;
        char **d;

        assert_se(mkdtemp(tmp_dir) != NULL);

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
        assert_se(streq(search_dirs[0], "/dir1"));
        assert_se(streq(search_dirs[1], "/dir2"));
        assert_se(streq(search_dirs[2], "/dir2"));

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

static void test_path_startswith(void) {
        const char *p;

        log_info("/* %s */", __func__);

        p = path_startswith("/foo/bar/barfoo/", "/foo");
        assert_se(streq_ptr(p, "bar/barfoo/"));

        p = path_startswith("/foo/bar/barfoo/", "/foo/");
        assert_se(streq_ptr(p, "bar/barfoo/"));

        p = path_startswith("/foo/bar/barfoo/", "/");
        assert_se(streq_ptr(p, "foo/bar/barfoo/"));

        p = path_startswith("/foo/bar/barfoo/", "////");
        assert_se(streq_ptr(p, "foo/bar/barfoo/"));

        p = path_startswith("/foo/bar/barfoo/", "/foo//bar/////barfoo///");
        assert_se(streq_ptr(p, ""));

        p = path_startswith("/foo/bar/barfoo/", "/foo/bar/barfoo////");
        assert_se(streq_ptr(p, ""));

        p = path_startswith("/foo/bar/barfoo/", "/foo/bar///barfoo/");
        assert_se(streq_ptr(p, ""));

        p = path_startswith("/foo/bar/barfoo/", "/foo////bar/barfoo/");
        assert_se(streq_ptr(p, ""));

        p = path_startswith("/foo/bar/barfoo/", "////foo/bar/barfoo/");
        assert_se(streq_ptr(p, ""));

        p = path_startswith("/foo/bar/barfoo/", "/foo/bar/barfoo");
        assert_se(streq_ptr(p, ""));

        assert_se(!path_startswith("/foo/bar/barfoo/", "/foo/bar/barfooa/"));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/foo/bar/barfooa"));
        assert_se(!path_startswith("/foo/bar/barfoo/", ""));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/bar/foo"));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/f/b/b/"));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/foo/bar/barfo"));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/foo/bar/bar"));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/fo"));
}

static void test_prefix_root_one(const char *r, const char *p, const char *expected) {
        _cleanup_free_ char *s = NULL;
        const char *t;

        assert_se(s = path_join(r, p));
        assert_se(path_equal_ptr(s, expected));

        t = prefix_roota(r, p);
        assert_se(t);
        assert_se(path_equal_ptr(t, expected));
}

static void test_prefix_root(void) {
        log_info("/* %s */", __func__);

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

static void test_file_in_same_dir(void) {
        char *t;

        log_info("/* %s */", __func__);

        t = file_in_same_dir("/", "a");
        assert_se(streq(t, "/a"));
        free(t);

        t = file_in_same_dir("/", "/a");
        assert_se(streq(t, "/a"));
        free(t);

        t = file_in_same_dir("", "a");
        assert_se(streq(t, "a"));
        free(t);

        t = file_in_same_dir("a/", "a");
        assert_se(streq(t, "a/a"));
        free(t);

        t = file_in_same_dir("bar/foo", "bar");
        assert_se(streq(t, "bar/bar"));
        free(t);
}

static void test_last_path_component(void) {
        assert_se(last_path_component(NULL) == NULL);
        assert_se(streq(last_path_component("a/b/c"), "c"));
        assert_se(streq(last_path_component("a/b/c/"), "c/"));
        assert_se(streq(last_path_component("/"), "/"));
        assert_se(streq(last_path_component("//"), "/"));
        assert_se(streq(last_path_component("///"), "/"));
        assert_se(streq(last_path_component("."), "."));
        assert_se(streq(last_path_component("./."), "."));
        assert_se(streq(last_path_component("././"), "./"));
        assert_se(streq(last_path_component("././/"), ".//"));
        assert_se(streq(last_path_component("/foo/a"), "a"));
        assert_se(streq(last_path_component("/foo/a/"), "a/"));
        assert_se(streq(last_path_component(""), ""));
        assert_se(streq(last_path_component("a"), "a"));
        assert_se(streq(last_path_component("a/"), "a/"));
        assert_se(streq(last_path_component("/a"), "a"));
        assert_se(streq(last_path_component("/a/"), "a/"));
}

static void test_path_extract_filename_one(const char *input, const char *output, int ret) {
        _cleanup_free_ char *k = NULL;
        int r;

        r = path_extract_filename(input, &k);
        log_info_errno(r, "%s → %s/%m [expected: %s/%s]",
                       strnull(input),
                       strnull(k), /* strerror(r) is printed via %m, to avoid that the two strerror()'s overwrite each other's buffers */
                       strnull(output), ret < 0 ? strerror_safe(ret) : "-");
        assert_se(streq_ptr(k, output));
        assert_se(r == ret);
}

static void test_path_extract_filename(void) {
        log_info("/* %s */", __func__);

        test_path_extract_filename_one(NULL, NULL, -EINVAL);
        test_path_extract_filename_one("a/b/c", "c", 0);
        test_path_extract_filename_one("a/b/c/", "c", O_DIRECTORY);
        test_path_extract_filename_one("/", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("//", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one("///", NULL, -EADDRNOTAVAIL);
        test_path_extract_filename_one(".", NULL, -EINVAL);
        test_path_extract_filename_one("./.", NULL, -EINVAL);
        test_path_extract_filename_one("././", NULL, -EINVAL);
        test_path_extract_filename_one("././/", NULL, -EINVAL);
        test_path_extract_filename_one("/foo/a", "a", 0);
        test_path_extract_filename_one("/foo/a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("", NULL, -EINVAL);
        test_path_extract_filename_one("a", "a", 0);
        test_path_extract_filename_one("a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("/a", "a", 0);
        test_path_extract_filename_one("/a/", "a", O_DIRECTORY);
        test_path_extract_filename_one("/////////////a/////////////", "a", O_DIRECTORY);
        test_path_extract_filename_one("xx/.", NULL, -EINVAL);
        test_path_extract_filename_one("xx/..", NULL, -EINVAL);
        test_path_extract_filename_one("..", NULL, -EINVAL);
        test_path_extract_filename_one("/..", NULL, -EINVAL);
        test_path_extract_filename_one("../", NULL, -EINVAL);
        test_path_extract_filename_one(".", NULL, -EINVAL);
        test_path_extract_filename_one("/.", NULL, -EINVAL);
        test_path_extract_filename_one("./", NULL, -EINVAL);
}

static void test_path_extract_directory_one(const char *input, const char *output, int ret) {
        _cleanup_free_ char *k = NULL;
        int r;

        r = path_extract_directory(input, &k);
        log_info_errno(r, "%s → %s/%m [expected: %s/%s]",
                       strnull(input),
                       strnull(k), /* we output strerror_safe(r) via %m here, since otherwise the error buffer might be overwritten twice */
                       strnull(output), strerror_safe(ret));
        assert_se(streq_ptr(k, output));
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

static void test_path_extract_directory(void) {
        log_info("/* %s */", __func__);

        test_path_extract_directory_one(NULL, NULL, -EINVAL);
        test_path_extract_directory_one("a/b/c", "a/b", 0);
        test_path_extract_directory_one("a/b/c/", "a/b", 0);
        test_path_extract_directory_one("/", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("//", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one("///", NULL, -EADDRNOTAVAIL);
        test_path_extract_directory_one(".", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("./.", ".", 0);
        test_path_extract_directory_one("././", ".", 0);
        test_path_extract_directory_one("././/", ".", 0);
        test_path_extract_directory_one("/foo/a", "/foo", 0);
        test_path_extract_directory_one("/foo/a/", "/foo", 0);
        test_path_extract_directory_one("", NULL, -EINVAL);
        test_path_extract_directory_one("a", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("a/", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("/a", "/", 0);
        test_path_extract_directory_one("/a/", "/", 0);
        test_path_extract_directory_one("/////////////a/////////////", "/", 0);
        test_path_extract_directory_one("xx/.", "xx", 0);
        test_path_extract_directory_one("xx/..", "xx", 0);
        test_path_extract_directory_one("..", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("/..", "/", 0);
        test_path_extract_directory_one("../", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one(".", NULL, -EDESTADDRREQ);
        test_path_extract_directory_one("/.", "/", 0);
        test_path_extract_directory_one("./", NULL, -EDESTADDRREQ);
}

static void test_filename_is_valid(void) {
        char foo[NAME_MAX+2];

        log_info("/* %s */", __func__);

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

static void test_path_is_valid(void) {
        char foo[PATH_MAX+2];
        const char *c;

        log_info("/* %s */", __func__);

        assert_se(!path_is_valid(""));
        assert_se(path_is_valid("/bar/foo"));
        assert_se(path_is_valid("/bar/foo/"));
        assert_se(path_is_valid("/bar/foo/"));
        assert_se(path_is_valid("//bar//foo//"));
        assert_se(path_is_valid("/"));
        assert_se(path_is_valid("/////"));
        assert_se(path_is_valid("/////.///.////...///..//."));
        assert_se(path_is_valid("."));
        assert_se(path_is_valid(".."));
        assert_se(path_is_valid("bar/foo"));
        assert_se(path_is_valid("bar/foo/"));
        assert_se(path_is_valid("bar//"));

        memset(foo, 'a', sizeof(foo) -1);
        char_array_0(foo);

        assert_se(!path_is_valid(foo));

        c = strjoina("/xxx/", foo, "/yyy");
        assert_se(!path_is_valid(c));

        assert_se(path_is_valid("foo_bar-333"));
        assert_se(path_is_valid("o.o"));
}

static void test_hidden_or_backup_file(void) {
        log_info("/* %s */", __func__);

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

static void test_systemd_installation_has_version(const char *path) {
        int r;
        const unsigned versions[] = {0, 231, PROJECT_VERSION, 999};
        unsigned i;

        log_info("/* %s */", __func__);

        for (i = 0; i < ELEMENTSOF(versions); i++) {
                r = systemd_installation_has_version(path, versions[i]);
                assert_se(r >= 0);
                log_info("%s has systemd >= %u: %s",
                         path ?: "Current installation", versions[i], yes_no(r));
        }
}

static void test_skip_dev_prefix(void) {
        log_info("/* %s */", __func__);

        assert_se(streq(skip_dev_prefix("/"), "/"));
        assert_se(streq(skip_dev_prefix("/dev"), ""));
        assert_se(streq(skip_dev_prefix("/dev/"), ""));
        assert_se(streq(skip_dev_prefix("/dev/foo"), "foo"));
        assert_se(streq(skip_dev_prefix("/dev/foo/bar"), "foo/bar"));
        assert_se(streq(skip_dev_prefix("//dev"), ""));
        assert_se(streq(skip_dev_prefix("//dev//"), ""));
        assert_se(streq(skip_dev_prefix("/dev///foo"), "foo"));
        assert_se(streq(skip_dev_prefix("///dev///foo///bar"), "foo///bar"));
        assert_se(streq(skip_dev_prefix("//foo"), "//foo"));
        assert_se(streq(skip_dev_prefix("foo"), "foo"));
}

static void test_empty_or_root(void) {
        log_info("/* %s */", __func__);

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

static void test_path_startswith_set(void) {
        log_info("/* %s */", __func__);

        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/foo/bar", "/zzz"), ""));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/foo/", "/zzz"), "bar"));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/foo", "/zzz"), "bar"));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "/", "/zzz"), "foo/bar"));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar", "/foo/quux", "", "/zzz"), NULL));

        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/foo/bar", "/zzz"), NULL));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/foo/", "/zzz"), "bar2"));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/foo", "/zzz"), "bar2"));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "/", "/zzz"), "foo/bar2"));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo/bar2", "/foo/quux", "", "/zzz"), NULL));

        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/foo/bar", "/zzz"), NULL));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/foo/", "/zzz"), NULL));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/foo", "/zzz"), NULL));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "/", "/zzz"), "foo2/bar"));
        assert_se(streq_ptr(PATH_STARTSWITH_SET("/foo2/bar", "/foo/quux", "", "/zzz"), NULL));
}

static void test_path_startswith_strv(void) {
        log_info("/* %s */", __func__);

        assert_se(streq_ptr(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/foo/bar", "/zzz")), ""));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/foo/", "/zzz")), "bar"));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/foo", "/zzz")), "bar"));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "/", "/zzz")), "foo/bar"));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar", STRV_MAKE("/foo/quux", "", "/zzz")), NULL));

        assert_se(streq_ptr(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/foo/bar", "/zzz")), NULL));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/foo/", "/zzz")), "bar2"));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/foo", "/zzz")), "bar2"));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "/", "/zzz")), "foo/bar2"));
        assert_se(streq_ptr(path_startswith_strv("/foo/bar2", STRV_MAKE("/foo/quux", "", "/zzz")), NULL));

        assert_se(streq_ptr(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/foo/bar", "/zzz")), NULL));
        assert_se(streq_ptr(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/foo/", "/zzz")), NULL));
        assert_se(streq_ptr(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/foo", "/zzz")), NULL));
        assert_se(streq_ptr(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "/", "/zzz")), "foo2/bar"));
        assert_se(streq_ptr(path_startswith_strv("/foo2/bar", STRV_MAKE("/foo/quux", "", "/zzz")), NULL));
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        log_info("PATH_MAX=%zu\n"
                 "FILENAME_MAX=%zu\n"
                 "NAME_MAX=%zu",
                 (size_t) PATH_MAX,
                 (size_t) FILENAME_MAX,
                 (size_t) NAME_MAX);

        assert_cc(FILENAME_MAX == PATH_MAX);

        test_print_paths();
        test_path();
        test_path_equal_root();
        test_find_executable_full();
        test_find_executable(argv[0]);
        test_find_executable_exec();
        test_prefixes();
        test_path_join();
        test_fsck_exists();
        test_make_relative();
        test_strv_resolve();
        test_path_startswith();
        test_prefix_root();
        test_file_in_same_dir();
        test_last_path_component();
        test_path_extract_filename();
        test_path_extract_directory();
        test_filename_is_valid();
        test_path_is_valid();
        test_hidden_or_backup_file();
        test_skip_dev_prefix();
        test_empty_or_root();
        test_path_startswith_set();
        test_path_startswith_strv();

        test_systemd_installation_has_version(argv[1]); /* NULL is OK */

        return 0;
}
