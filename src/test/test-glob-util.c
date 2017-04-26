/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <fcntl.h>
#include <glob.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glob-util.h"
#include "macro.h"
#include "rm-rf.h"

static void test_glob_exists(void) {
        char name[] = "/tmp/test-glob_exists.XXXXXX";
        int fd = -1;
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

static void test_glob_no_dot(void) {
        char template[] = "/tmp/test-glob-util.XXXXXXX";
        const char *fn;

        _cleanup_globfree_ glob_t g = {
                .gl_closedir = (void (*)(void *)) closedir,
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

static void test_safe_glob(void) {
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
        assert_se(streq(g.gl_pathv[0], fname));
        assert_se(g.gl_pathv[1] == NULL);

        (void) rm_rf(template, REMOVE_ROOT|REMOVE_PHYSICAL);
}

int main(void) {
        test_glob_exists();
        test_glob_no_dot();
        test_safe_glob();

        return 0;
}
