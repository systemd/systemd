/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Michael Marineau
***/

#include <sys/stat.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "fd-util.h"
#include "fileio.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(conf_files_list) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_strv_free_ char **result = NULL;
        const char *search1, *search2, *search1_a, *search1_b, *search1_c, *search2_aa;

        tfd = mkdtemp_open("/tmp/test-conf-files-XXXXXX", O_PATH, &t);
        assert(tfd >= 0);

        assert_se(mkdirat(tfd, "dir1", 0755) >= 0);
        assert_se(mkdirat(tfd, "dir2", 0755) >= 0);

        search1 = strjoina(t, "/dir1/");
        search2 = strjoina(t, "/dir2/");

        FOREACH_STRING(p, "a.conf", "b.conf", "c.foo") {
                _cleanup_free_ char *path = NULL;

                assert_se(path = path_join(search1, p));
                assert_se(write_string_file(path, "foobar", WRITE_STRING_FILE_CREATE) >= 0);
        }

        assert_se(symlinkat("/dev/null", tfd, "dir1/m.conf") >= 0);

        FOREACH_STRING(p, "a.conf", "aa.conf", "m.conf") {
                _cleanup_free_ char *path = NULL;

                assert_se(path = path_join(search2, p));
                assert_se(write_string_file(path, "hogehoge", WRITE_STRING_FILE_CREATE) >= 0);
        }

        search1_a = strjoina(search1, "a.conf");
        search1_b = strjoina(search1, "b.conf");
        search1_c = strjoina(search1, "c.foo");
        search2_aa = strjoina(search2, "aa.conf");

        /* search dir1 without suffix */
        assert_se(conf_files_list(&result, NULL, NULL, CONF_FILES_FILTER_MASKED, search1) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        assert_se(conf_files_list(&result, NULL, t, CONF_FILES_FILTER_MASKED, "/dir1/") >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        assert_se(conf_files_list_at(&result, NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED, search1) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        assert_se(conf_files_list_at(&result, NULL, tfd, CONF_FILES_FILTER_MASKED, "/dir1/") >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE("dir1/a.conf", "dir1/b.conf", "dir1/c.foo")));

        result = strv_free(result);

        /* search dir1 with suffix */
        assert_se(conf_files_list(&result, ".conf", NULL, CONF_FILES_FILTER_MASKED, search1) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search1_b)));

        result = strv_free(result);

        assert_se(conf_files_list(&result, ".conf", t, CONF_FILES_FILTER_MASKED, "/dir1/") >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search1_b)));

        result = strv_free(result);

        assert_se(conf_files_list_at(&result, ".conf", AT_FDCWD, CONF_FILES_FILTER_MASKED, search1) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search1_b)));

        result = strv_free(result);

        assert_se(conf_files_list_at(&result, ".conf", tfd, CONF_FILES_FILTER_MASKED, "/dir1/") >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE("dir1/a.conf", "dir1/b.conf")));

        result = strv_free(result);

        /* search two dirs */
        assert_se(conf_files_list_strv(&result, ".conf", NULL, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST(search1, search2)) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search2_aa, search1_b)));

        result = strv_free(result);

        assert_se(conf_files_list_strv(&result, ".conf", t, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST("/dir1/", "/dir2/")) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search2_aa, search1_b)));

        result = strv_free(result);

        assert_se(conf_files_list_strv_at(&result, ".conf", AT_FDCWD, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST(search1, search2)) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE(search1_a, search2_aa, search1_b)));

        result = strv_free(result);

        assert_se(conf_files_list_strv_at(&result, ".conf", tfd, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST("/dir1/", "/dir2/")) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE("dir1/a.conf", "dir2/aa.conf", "dir1/b.conf")));

        result = strv_free(result);

        /* filename only */
        assert_se(conf_files_list_strv(&result, ".conf", NULL, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST(search1, search2)) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf")));

        result = strv_free(result);

        assert_se(conf_files_list_strv(&result, ".conf", t, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST("/dir1/", "/dir2/")) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf")));

        result = strv_free(result);

        assert_se(conf_files_list_strv_at(&result, ".conf", AT_FDCWD, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST(search1, search2)) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf")));

        result = strv_free(result);

        assert_se(conf_files_list_strv_at(&result, ".conf", tfd, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST("/dir1/", "/dir2/")) >= 0);
        strv_print(result);
        assert_se(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf")));
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
