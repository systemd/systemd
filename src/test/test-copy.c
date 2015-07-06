/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

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

#include <unistd.h>

#include "copy.h"
#include "path-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "strv.h"
#include "macro.h"
#include "util.h"
#include "rm-rf.h"

static void test_copy_file(void) {
        _cleanup_free_ char *buf = NULL;
        char fn[] = "/tmp/test-copy_file.XXXXXX";
        char fn_copy[] = "/tmp/test-copy_file.XXXXXX";
        size_t sz = 0;
        int fd;

        fd = mkostemp_safe(fn, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        close(fd);

        fd = mkostemp_safe(fn_copy, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        close(fd);

        assert_se(write_string_file(fn, "foo bar bar bar foo", WRITE_STRING_FILE_CREATE) == 0);

        assert_se(copy_file(fn, fn_copy, 0, 0644, 0) == 0);

        assert_se(read_full_file(fn_copy, &buf, &sz) == 0);
        assert_se(streq(buf, "foo bar bar bar foo\n"));
        assert_se(sz == 20);

        unlink(fn);
        unlink(fn_copy);
}

static void test_copy_file_fd(void) {
        char in_fn[] = "/tmp/test-copy-file-fd-XXXXXX";
        char out_fn[] = "/tmp/test-copy-file-fd-XXXXXX";
        _cleanup_close_ int in_fd = -1, out_fd = -1;
        char text[] = "boohoo\nfoo\n\tbar\n";
        char buf[64] = {0};

        in_fd = mkostemp_safe(in_fn, O_RDWR);
        assert_se(in_fd >= 0);
        out_fd = mkostemp_safe(out_fn, O_RDWR);
        assert_se(out_fd >= 0);

        assert_se(write_string_file(in_fn, text, WRITE_STRING_FILE_CREATE) == 0);
        assert_se(copy_file_fd("/a/file/which/does/not/exist/i/guess", out_fd, true) < 0);
        assert_se(copy_file_fd(in_fn, out_fd, true) >= 0);
        assert_se(lseek(out_fd, SEEK_SET, 0) == 0);

        assert_se(read(out_fd, buf, sizeof(buf)) == sizeof(text) - 1);
        assert_se(streq(buf, text));

        unlink(in_fn);
        unlink(out_fn);
}

static void test_copy_tree(void) {
        char original_dir[] = "/tmp/test-copy_tree/";
        char copy_dir[] = "/tmp/test-copy_tree-copy/";
        char **files = STRV_MAKE("file", "dir1/file", "dir1/dir2/file", "dir1/dir2/dir3/dir4/dir5/file");
        char **links = STRV_MAKE("link", "file",
                                 "link2", "dir1/file");
        char **p, **link;

        (void) rm_rf(copy_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(original_dir, REMOVE_ROOT|REMOVE_PHYSICAL);

        STRV_FOREACH(p, files) {
                char *f = strjoina(original_dir, *p);

                assert_se(mkdir_parents(f, 0755) >= 0);
                assert_se(write_string_file(f, "file", WRITE_STRING_FILE_CREATE) == 0);
        }

        STRV_FOREACH_PAIR(link, p, links) {
                char *f = strjoina(original_dir, *p);
                char *l = strjoina(original_dir, *link);

                assert_se(mkdir_parents(l, 0755) >= 0);
                assert_se(symlink(f, l) == 0);
        }

        assert_se(copy_tree(original_dir, copy_dir, true) == 0);

        STRV_FOREACH(p, files) {
                _cleanup_free_ char *buf = NULL;
                size_t sz = 0;
                char *f = strjoina(copy_dir, *p);

                assert_se(access(f, F_OK) == 0);
                assert_se(read_full_file(f, &buf, &sz) == 0);
                assert_se(streq(buf, "file\n"));
        }

        STRV_FOREACH_PAIR(link, p, links) {
                _cleanup_free_ char *target = NULL;
                char *f = strjoina(original_dir, *p);
                char *l = strjoina(copy_dir, *link);

                assert_se(readlink_and_canonicalize(l, &target) == 0);
                assert_se(path_equal(f, target));
        }

        assert_se(copy_tree(original_dir, copy_dir, false) < 0);
        assert_se(copy_tree("/tmp/inexistent/foo/bar/fsdoi", copy_dir, false) < 0);

        (void) rm_rf(copy_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(original_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_copy_bytes(void) {
        _cleanup_close_pair_ int pipefd[2] = {-1, -1};
        _cleanup_close_ int infd = -1;
        int r, r2;
        char buf[1024], buf2[1024];

        infd = open("/usr/lib/os-release", O_RDONLY|O_CLOEXEC);
        if (infd < 0)
                infd = open("/etc/os-release", O_RDONLY|O_CLOEXEC);
        assert_se(infd >= 0);

        assert_se(pipe2(pipefd, O_CLOEXEC) == 0);

        r = copy_bytes(infd, pipefd[1], (off_t) -1, false);
        assert_se(r == 0);

        r = read(pipefd[0], buf, sizeof(buf));
        assert_se(r >= 0);

        assert_se(lseek(infd, 0, SEEK_SET) == 0);
        r2 = read(infd, buf2, sizeof(buf2));
        assert_se(r == r2);

        assert_se(strneq(buf, buf2, r));

        /* test copy_bytes with invalid descriptors */
        r = copy_bytes(pipefd[0], pipefd[0], 1, false);
        assert_se(r == -EBADF);

        r = copy_bytes(pipefd[1], pipefd[1], 1, false);
        assert_se(r == -EBADF);

        r = copy_bytes(pipefd[1], infd, 1, false);
        assert_se(r == -EBADF);
}

int main(int argc, char *argv[]) {
        test_copy_file();
        test_copy_file_fd();
        test_copy_tree();
        test_copy_bytes();

        return 0;
}
