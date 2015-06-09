/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>

#include "path-util.h"
#include "util.h"
#include "macro.h"
#include "strv.h"
#include "rm-rf.h"

#define test_path_compare(a, b, result) {                 \
                assert_se(path_compare(a, b) == result);  \
                assert_se(path_compare(b, a) == -result); \
                assert_se(path_equal(a, b) == !result);   \
                assert_se(path_equal(b, a) == !result);   \
        }

static void test_path(void) {
        _cleanup_close_ int fd = -1;

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

#define test_parent(x, y) {                                \
                _cleanup_free_ char *z = NULL;             \
                int r = path_get_parent(x, &z);            \
                printf("expected: %s\n", y ? y : "error"); \
                printf("actual: %s\n", r<0 ? "error" : z); \
                assert_se((y==NULL) ^ (r==0));             \
                assert_se(y==NULL || path_equal(z, y));    \
        }

        test_parent("./aa/bb/../file.da.", "./aa/bb/..");
        test_parent("/aa///.file", "/aa///");
        test_parent("/aa///file...", "/aa///");
        test_parent("file.../", NULL);

        fd = open("/", O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY);
        assert_se(fd >= 0);
        assert_se(fd_is_mount_point(fd, "/", 0) > 0);

        {
                char p1[] = "aaa/bbb////ccc";
                char p2[] = "//aaa/.////ccc";
                char p3[] = "/./";

                assert_se(path_equal(path_kill_slashes(p1), "aaa/bbb/ccc"));
                assert_se(path_equal(path_kill_slashes(p2), "/aaa/./ccc"));
                assert_se(path_equal(path_kill_slashes(p3), "/./"));
        }
}

static void test_find_binary(const char *self, bool local) {
        char *p;

        assert_se(find_binary("/bin/sh", local, &p) == 0);
        puts(p);
        assert_se(streq(p, "/bin/sh"));
        free(p);

        assert_se(find_binary(self, local, &p) == 0);
        puts(p);
        assert_se(endswith(p, "/test-path-util"));
        assert_se(path_is_absolute(p));
        free(p);

        assert_se(find_binary("sh", local, &p) == 0);
        puts(p);
        assert_se(endswith(p, "/sh"));
        assert_se(path_is_absolute(p));
        free(p);

        assert_se(find_binary("xxxx-xxxx", local, &p) == -ENOENT);

        assert_se(find_binary("/some/dir/xxxx-xxxx", local, &p) ==
                  (local ? -ENOENT : 0));
        if (!local)
                free(p);
}

static void test_prefixes(void) {
        static const char* values[] = { "/a/b/c/d", "/a/b/c", "/a/b", "/a", "", NULL};
        unsigned i;
        char s[PATH_MAX];
        bool b;

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

#define test_join(root, path, rest, expected) {  \
                _cleanup_free_ char *z = NULL;   \
                z = path_join(root, path, rest); \
                assert_se(streq(z, expected));   \
        }

        test_join("/root", "/a/b", "/c", "/root/a/b/c");
        test_join("/root", "a/b", "c", "/root/a/b/c");
        test_join("/root", "/a/b", "c", "/root/a/b/c");
        test_join("/root", "/", "c", "/root/c");
        test_join("/root", "/", NULL, "/root/");

        test_join(NULL, "/a/b", "/c", "/a/b/c");
        test_join(NULL, "a/b", "c", "a/b/c");
        test_join(NULL, "/a/b", "c", "/a/b/c");
        test_join(NULL, "/", "c", "/c");
        test_join(NULL, "/", NULL, "/");
}

static void test_fsck_exists(void) {
        /* Ensure we use a sane default for PATH. */
        unsetenv("PATH");

        /* fsck.minix is provided by util-linux and will probably exist. */
        assert_se(fsck_exists("minix") == 0);

        assert_se(fsck_exists("AbCdE") == -ENOENT);
}

static void test_make_relative(void) {
        char *result;

        assert_se(path_make_relative("some/relative/path", "/some/path", &result) < 0);
        assert_se(path_make_relative("/some/path", "some/relative/path", &result) < 0);

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
        test("//extra/////slashes///won't////fool///anybody//", "////extra///slashes////are/just///fine///", "../../../are/just/fine");
}

static void test_strv_resolve(void) {
        char tmp_dir[] = "/tmp/test-path-util-XXXXXX";
        _cleanup_strv_free_ char **search_dirs = NULL;
        _cleanup_strv_free_ char **absolute_dirs = NULL;
        char **d;

        assert_se(mkdtemp(tmp_dir) != NULL);

        search_dirs = strv_new("/dir1", "/dir2", "/dir3", NULL);
        assert_se(search_dirs);
        STRV_FOREACH(d, search_dirs) {
                char *p = strappend(tmp_dir, *d);
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
        assert_se(path_startswith("/foo/bar/barfoo/", "/foo"));
        assert_se(path_startswith("/foo/bar/barfoo/", "/foo/"));
        assert_se(path_startswith("/foo/bar/barfoo/", "/"));
        assert_se(path_startswith("/foo/bar/barfoo/", "////"));
        assert_se(path_startswith("/foo/bar/barfoo/", "/foo//bar/////barfoo///"));
        assert_se(path_startswith("/foo/bar/barfoo/", "/foo/bar/barfoo////"));
        assert_se(path_startswith("/foo/bar/barfoo/", "/foo/bar///barfoo/"));
        assert_se(path_startswith("/foo/bar/barfoo/", "/foo////bar/barfoo/"));
        assert_se(path_startswith("/foo/bar/barfoo/", "////foo/bar/barfoo/"));
        assert_se(path_startswith("/foo/bar/barfoo/", "/foo/bar/barfoo"));

        assert_se(!path_startswith("/foo/bar/barfoo/", "/foo/bar/barfooa/"));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/foo/bar/barfooa"));
        assert_se(!path_startswith("/foo/bar/barfoo/", ""));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/bar/foo"));
        assert_se(!path_startswith("/foo/bar/barfoo/", "/f/b/b/"));
}

static void test_prefix_root_one(const char *r, const char *p, const char *expected) {
        _cleanup_free_ char *s = NULL;
        const char *t;

        assert_se(s = prefix_root(r, p));
        assert_se(streq_ptr(s, expected));

        t = prefix_roota(r, p);
        assert_se(t);
        assert_se(streq_ptr(t, expected));
}

static void test_prefix_root(void) {
        test_prefix_root_one("/", "/foo", "/foo");
        test_prefix_root_one(NULL, "/foo", "/foo");
        test_prefix_root_one("", "/foo", "/foo");
        test_prefix_root_one("///", "/foo", "/foo");
        test_prefix_root_one("/", "////foo", "/foo");
        test_prefix_root_one(NULL, "////foo", "/foo");

        test_prefix_root_one("/foo", "/bar", "/foo/bar");
        test_prefix_root_one("/foo", "bar", "/foo/bar");
        test_prefix_root_one("foo", "bar", "foo/bar");
        test_prefix_root_one("/foo/", "/bar", "/foo/bar");
        test_prefix_root_one("/foo/", "//bar", "/foo/bar");
        test_prefix_root_one("/foo///", "//bar", "/foo/bar");
}

static void test_path_is_mount_point(void) {
        int fd;
        char tmp_dir[] = "/tmp/test-path-is-mount-point-XXXXXX";
        _cleanup_free_ char *file1 = NULL, *file2 = NULL, *link1 = NULL, *link2 = NULL;
        _cleanup_free_ char *dir1 = NULL, *dir1file = NULL, *dirlink1 = NULL, *dirlink1file = NULL;
        _cleanup_free_ char *dir2 = NULL, *dir2file = NULL;

        assert_se(path_is_mount_point("/", AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/", 0) > 0);

        assert_se(path_is_mount_point("/proc", AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/proc", 0) > 0);

        assert_se(path_is_mount_point("/proc/1", AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point("/proc/1", 0) == 0);

        assert_se(path_is_mount_point("/sys", AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/sys", 0) > 0);

        /* we'll create a hierarchy of different kinds of dir/file/link
         * layouts:
         *
         * <tmp>/file1, <tmp>/file2
         * <tmp>/link1 -> file1, <tmp>/link2 -> file2
         * <tmp>/dir1/
         * <tmp>/dir1/file
         * <tmp>/dirlink1 -> dir1
         * <tmp>/dirlink1file -> dirlink1/file
         * <tmp>/dir2/
         * <tmp>/dir2/file
         */

        /* file mountpoints */
        assert_se(mkdtemp(tmp_dir) != NULL);
        file1 = path_join(NULL, tmp_dir, "file1");
        assert_se(file1);
        file2 = path_join(NULL, tmp_dir, "file2");
        assert_se(file2);
        fd = open(file1, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
        assert_se(fd > 0);
        close(fd);
        fd = open(file2, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
        assert_se(fd > 0);
        close(fd);
        link1 = path_join(NULL, tmp_dir, "link1");
        assert_se(link1);
        assert_se(symlink("file1", link1) == 0);
        link2 = path_join(NULL, tmp_dir, "link2");
        assert_se(link1);
        assert_se(symlink("file2", link2) == 0);

        assert_se(path_is_mount_point(file1, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(file1, 0) == 0);
        assert_se(path_is_mount_point(link1, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(link1, 0) == 0);

        /* directory mountpoints */
        dir1 = path_join(NULL, tmp_dir, "dir1");
        assert_se(dir1);
        assert_se(mkdir(dir1, 0755) == 0);
        dirlink1 = path_join(NULL, tmp_dir, "dirlink1");
        assert_se(dirlink1);
        assert_se(symlink("dir1", dirlink1) == 0);
        dirlink1file = path_join(NULL, tmp_dir, "dirlink1file");
        assert_se(dirlink1file);
        assert_se(symlink("dirlink1/file", dirlink1file) == 0);
        dir2 = path_join(NULL, tmp_dir, "dir2");
        assert_se(dir2);
        assert_se(mkdir(dir2, 0755) == 0);

        assert_se(path_is_mount_point(dir1, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dir1, 0) == 0);
        assert_se(path_is_mount_point(dirlink1, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dirlink1, 0) == 0);

        /* file in subdirectory mountpoints */
        dir1file = path_join(NULL, dir1, "file");
        assert_se(dir1file);
        fd = open(dir1file, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
        assert_se(fd > 0);
        close(fd);

        assert_se(path_is_mount_point(dir1file, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dir1file, 0) == 0);
        assert_se(path_is_mount_point(dirlink1file, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dirlink1file, 0) == 0);

        /* these tests will only work as root */
        if (mount(file1, file2, NULL, MS_BIND, NULL) >= 0) {
                int rt, rf, rlt, rlf, rl1t, rl1f;

                /* files */
                /* capture results in vars, to avoid dangling mounts on failure */
                rf = path_is_mount_point(file2, 0);
                rt = path_is_mount_point(file2, AT_SYMLINK_FOLLOW);
                rlf = path_is_mount_point(link2, 0);
                rlt = path_is_mount_point(link2, AT_SYMLINK_FOLLOW);

                assert_se(umount(file2) == 0);

                assert_se(rf == 1);
                assert_se(rt == 1);
                assert_se(rlf == 0);
                assert_se(rlt == 1);

                /* dirs */
                dir2file = path_join(NULL, dir2, "file");
                assert_se(dir2file);
                fd = open(dir2file, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
                assert_se(fd > 0);
                close(fd);

                assert_se(mount(dir2, dir1, NULL, MS_BIND, NULL) >= 0);

                rf = path_is_mount_point(dir1, 0);
                rt = path_is_mount_point(dir1, AT_SYMLINK_FOLLOW);
                rlf = path_is_mount_point(dirlink1, 0);
                rlt = path_is_mount_point(dirlink1, AT_SYMLINK_FOLLOW);
                /* its parent is a mount point, but not /file itself */
                rl1f = path_is_mount_point(dirlink1file, 0);
                rl1t = path_is_mount_point(dirlink1file, AT_SYMLINK_FOLLOW);

                assert_se(umount(dir1) == 0);

                assert_se(rf == 1);
                assert_se(rt == 1);
                assert_se(rlf == 0);
                assert_se(rlt == 1);
                assert_se(rl1f == 0);
                assert_se(rl1t == 0);

        } else
                printf("Skipping bind mount file test: %m\n");

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

int main(int argc, char **argv) {
        test_path();
        test_find_binary(argv[0], true);
        test_find_binary(argv[0], false);
        test_prefixes();
        test_path_join();
        test_fsck_exists();
        test_make_relative();
        test_strv_resolve();
        test_path_startswith();
        test_prefix_root();
        test_path_is_mount_point();

        return 0;
}
