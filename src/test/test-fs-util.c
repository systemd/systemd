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

#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static void test_chase_symlinks(void) {
        _cleanup_free_ char *result = NULL;
        char temp[] = "/tmp/test-chase.XXXXXX";
        const char *top, *p, *q;
        int r;

        assert_se(mkdtemp(temp));

        top = strjoina(temp, "/top");
        assert_se(mkdir(top, 0700) >= 0);

        p = strjoina(top, "/dot");
        assert_se(symlink(".", p) >= 0);

        p = strjoina(top, "/dotdot");
        assert_se(symlink("..", p) >= 0);

        p = strjoina(top, "/dotdota");
        assert_se(symlink("../a", p) >= 0);

        p = strjoina(temp, "/a");
        assert_se(symlink("b", p) >= 0);

        p = strjoina(temp, "/b");
        assert_se(symlink("/usr", p) >= 0);

        p = strjoina(temp, "/start");
        assert_se(symlink("top/dot/dotdota", p) >= 0);

        /* Paths that use symlinks underneath the "root" */

        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r == -ENOENT);

        q = strjoina(temp, "/usr");

        r = chase_symlinks(p, temp, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, q));

        assert_se(mkdir(q, 0700) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, q));

        p = strjoina(temp, "/slash");
        assert_se(symlink("/", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, temp));

        /* Paths that would "escape" outside of the "root" */

        p = strjoina(temp, "/6dots");
        assert_se(symlink("../../..", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, temp));

        p = strjoina(temp, "/6dotsusr");
        assert_se(symlink("../../../usr", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, q));

        p = strjoina(temp, "/top/8dotsusr");
        assert_se(symlink("../../../../usr", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, q));

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        assert_se(symlink("///usr///", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, q));

        /* Paths using . */

        result = mfree(result);
        r = chase_symlinks("/etc/./.././", NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));

        result = mfree(result);
        r = chase_symlinks("/etc/./.././", "/etc", 0, &result);
        assert_se(r > 0 && path_equal(result, "/etc"));

        result = mfree(result);
        r = chase_symlinks("/etc/machine-id/foo", NULL, 0, &result);
        assert_se(r == -ENOTDIR);

        /* Path that loops back to self */

        result = mfree(result);
        p = strjoina(temp, "/recursive-symlink");
        assert_se(symlink("recursive-symlink", p) >= 0);
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ELOOP);

        /* Path which doesn't exist */

        p = strjoina(temp, "/idontexist");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        p = strjoina(temp, "/idontexist/meneither");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        /* Path which doesn't exist, but contains weird stuff */

        p = strjoina(temp, "/idontexist/..");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == -ENOENT);

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/top");
        assert_se(symlink(q, p) >= 0);
        p = strjoina(temp, "/target/idontexist");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        assert_se(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

static void test_unlink_noerrno(void) {
        char name[] = "/tmp/test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);

        {
                PROTECT_ERRNO;
                errno = -42;
                assert_se(unlink_noerrno(name) >= 0);
                assert_se(errno == -42);
                assert_se(unlink_noerrno(name) < 0);
                assert_se(errno == -42);
        }
}

static void test_readlink_and_make_absolute(void) {
        char tempdir[] = "/tmp/test-readlink_and_make_absolute";
        char name[] = "/tmp/test-readlink_and_make_absolute/original";
        char name2[] = "test-readlink_and_make_absolute/original";
        char name_alias[] = "/tmp/test-readlink_and_make_absolute-alias";
        char *r = NULL;

        assert_se(mkdir_safe(tempdir, 0755, getuid(), getgid()) >= 0);
        assert_se(touch(name) >= 0);

        assert_se(symlink(name, name_alias) >= 0);
        assert_se(readlink_and_make_absolute(name_alias, &r) >= 0);
        assert_se(streq(r, name));
        free(r);
        assert_se(unlink(name_alias) >= 0);

        assert_se(chdir(tempdir) >= 0);
        assert_se(symlink(name2, name_alias) >= 0);
        assert_se(readlink_and_make_absolute(name_alias, &r) >= 0);
        assert_se(streq(r, name));
        free(r);
        assert_se(unlink(name_alias) >= 0);

        assert_se(rm_rf(tempdir, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

static void test_get_files_in_directory(void) {
        _cleanup_strv_free_ char **l = NULL, **t = NULL;

        assert_se(get_files_in_directory("/tmp", &l) >= 0);
        assert_se(get_files_in_directory(".", &t) >= 0);
        assert_se(get_files_in_directory(".", NULL) >= 0);
}

static void test_var_tmp(void) {
        _cleanup_free_ char *tmpdir_backup = NULL, *temp_backup = NULL, *tmp_backup = NULL;
        const char *tmp_dir = NULL, *t;

        t = getenv("TMPDIR");
        if (t) {
                tmpdir_backup = strdup(t);
                assert_se(tmpdir_backup);
        }

        t = getenv("TEMP");
        if (t) {
                temp_backup = strdup(t);
                assert_se(temp_backup);
        }

        t = getenv("TMP");
        if (t) {
                tmp_backup = strdup(t);
                assert_se(tmp_backup);
        }

        assert(unsetenv("TMPDIR") >= 0);
        assert(unsetenv("TEMP") >= 0);
        assert(unsetenv("TMP") >= 0);

        assert_se(var_tmp_dir(&tmp_dir) >= 0);
        assert_se(streq(tmp_dir, "/var/tmp"));

        assert_se(setenv("TMPDIR", "/tmp", true) >= 0);
        assert_se(streq(getenv("TMPDIR"), "/tmp"));

        assert_se(var_tmp_dir(&tmp_dir) >= 0);
        assert_se(streq(tmp_dir, "/tmp"));

        assert_se(setenv("TMPDIR", "/88_does_not_exist_88", true) >= 0);
        assert_se(streq(getenv("TMPDIR"), "/88_does_not_exist_88"));

        assert_se(var_tmp_dir(&tmp_dir) >= 0);
        assert_se(streq(tmp_dir, "/var/tmp"));

        if (tmpdir_backup)  {
                assert_se(setenv("TMPDIR", tmpdir_backup, true) >= 0);
                assert_se(streq(getenv("TMPDIR"), tmpdir_backup));
        }

        if (temp_backup)  {
                assert_se(setenv("TEMP", temp_backup, true) >= 0);
                assert_se(streq(getenv("TEMP"), temp_backup));
        }

        if (tmp_backup)  {
                assert_se(setenv("TMP", tmp_backup, true) >= 0);
                assert_se(streq(getenv("TMP"), tmp_backup));
        }
}

static void test_dot_or_dot_dot(void) {
        assert_se(!dot_or_dot_dot(NULL));
        assert_se(!dot_or_dot_dot(""));
        assert_se(!dot_or_dot_dot("xxx"));
        assert_se(dot_or_dot_dot("."));
        assert_se(dot_or_dot_dot(".."));
        assert_se(!dot_or_dot_dot(".foo"));
        assert_se(!dot_or_dot_dot("..foo"));
}

int main(int argc, char *argv[]) {
        test_unlink_noerrno();
        test_get_files_in_directory();
        test_readlink_and_make_absolute();
        test_var_tmp();
        test_chase_symlinks();
        test_dot_or_dot_dot();

        return 0;
}
