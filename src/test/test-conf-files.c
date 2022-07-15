/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Michael Marineau
***/

#include <stdarg.h>
#include <stdio.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "user-util.h"
#include "util.h"

static void setup_test_dir(char *tmp_dir, const char *files, ...) {
        va_list ap;

        assert_se(mkdtemp(tmp_dir));

        va_start(ap, files);
        while (files) {
                _cleanup_free_ char *path;

                assert_se(path = path_join(tmp_dir, files));
                assert_se(write_string_file(path, "foobar", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

                files = va_arg(ap, const char *);
        }
        va_end(ap);
}

static void test_conf_files_list_one(bool use_root) {
        char tmp_dir[] = "/tmp/test-conf-files-XXXXXX";
        _cleanup_strv_free_ char **found_files = NULL, **found_files2 = NULL;
        const char *root_dir, *search, *expect_a, *expect_b, *expect_c, *mask;

        log_info("/* %s(%s) */", __func__, yes_no(use_root));

        setup_test_dir(tmp_dir,
                       "/dir/a.conf",
                       "/dir/b.conf",
                       "/dir/c.foo",
                       NULL);

        mask = strjoina(tmp_dir, "/dir/d.conf");
        assert_se(symlink("/dev/null", mask) >= 0);

        if (use_root) {
                root_dir = tmp_dir;
                search = "/dir";
        } else {
                root_dir = NULL;
                search = strjoina(tmp_dir, "/dir");
        }

        expect_a = strjoina(tmp_dir, "/dir/a.conf");
        expect_b = strjoina(tmp_dir, "/dir/b.conf");
        expect_c = strjoina(tmp_dir, "/dir/c.foo");

        log_debug("/* Check when filtered by suffix */");

        assert_se(conf_files_list(&found_files, ".conf", root_dir, CONF_FILES_FILTER_MASKED, search) == 0);
        strv_print(found_files);

        assert_se(found_files);
        assert_se(streq_ptr(found_files[0], expect_a));
        assert_se(streq_ptr(found_files[1], expect_b));
        assert_se(!found_files[2]);

        log_debug("/* Check when unfiltered */");
        assert_se(conf_files_list(&found_files2, NULL, root_dir, CONF_FILES_FILTER_MASKED, search) == 0);
        strv_print(found_files2);

        assert_se(found_files2);
        assert_se(streq_ptr(found_files2[0], expect_a));
        assert_se(streq_ptr(found_files2[1], expect_b));
        assert_se(streq_ptr(found_files2[2], expect_c));
        assert_se(!found_files2[3]);

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

TEST(conf_files_list) {
        test_conf_files_list_one(false);
        test_conf_files_list_one(true);
}

static void test_conf_files_insert_one(const char *root) {
        _cleanup_strv_free_ char **s = NULL;

        log_info("/* %s root=%s */", __func__, strempty(root));

        char **dirs = STRV_MAKE("/dir1", "/dir2", "/dir3");

        _cleanup_free_ const char
                *foo1 = path_join(root, "/dir1/foo.conf"),
                *foo2 = path_join(root, "/dir2/foo.conf"),
                *bar2 = path_join(root, "/dir2/bar.conf"),
                *zzz3 = path_join(root, "/dir3/zzz.conf"),
                *whatever = path_join(root, "/whatever.conf");

        assert_se(conf_files_insert(&s, root, dirs, "/dir2/foo.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(foo2)));

        /* The same file again, https://github.com/systemd/systemd/issues/11124 */
        assert_se(conf_files_insert(&s, root, dirs, "/dir2/foo.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(foo2)));

        /* Lower priority → new entry is ignored */
        assert_se(conf_files_insert(&s, root, dirs, "/dir3/foo.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(foo2)));

        /* Higher priority → new entry replaces */
        assert_se(conf_files_insert(&s, root, dirs, "/dir1/foo.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(foo1)));

        /* Earlier basename */
        assert_se(conf_files_insert(&s, root, dirs, "/dir2/bar.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(bar2, foo1)));

        /* Later basename */
        assert_se(conf_files_insert(&s, root, dirs, "/dir3/zzz.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(bar2, foo1, zzz3)));

        /* All lower priority → all ignored */
        assert_se(conf_files_insert(&s, root, dirs, "/dir3/zzz.conf") == 0);
        assert_se(conf_files_insert(&s, root, dirs, "/dir2/bar.conf") == 0);
        assert_se(conf_files_insert(&s, root, dirs, "/dir3/bar.conf") == 0);
        assert_se(conf_files_insert(&s, root, dirs, "/dir2/foo.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(bar2, foo1, zzz3)));

        /* Two entries that don't match any of the directories, but match basename */
        assert_se(conf_files_insert(&s, root, dirs, "/dir4/zzz.conf") == 0);
        assert_se(conf_files_insert(&s, root, dirs, "/zzz.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(bar2, foo1, zzz3)));

        /* An entry that doesn't match any of the directories, no match at all */
        assert_se(conf_files_insert(&s, root, dirs, "/whatever.conf") == 0);
        assert_se(strv_equal(s, STRV_MAKE(bar2, foo1, whatever, zzz3)));
}

TEST(conf_files_insert) {
        test_conf_files_insert_one(NULL);
        test_conf_files_insert_one("/root");
        test_conf_files_insert_one("/root/");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
