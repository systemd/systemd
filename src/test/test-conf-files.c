/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Michael Marineau
***/

#include <sys/stat.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(conf_files_list) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL, *t2 = NULL;
        _cleanup_close_ int tfd = -EBADF, tfd2 = -EBADF;
        _cleanup_strv_free_ char **result = NULL;
        const char *search1, *search2, *search3, *search1_a, *search1_b, *search1_c, *search2_aa;

        ASSERT_OK(tfd = mkdtemp_open("/tmp/test-conf-files-XXXXXX", O_PATH, &t));
        ASSERT_OK(tfd2 = mkdtemp_open("/tmp/test-conf-files-XXXXXX", O_PATH, &t2));

        ASSERT_OK(mkdirat(tfd, "dir1", 0755));
        ASSERT_OK(mkdirat(tfd, "dir2", 0755));
        ASSERT_OK(mkdirat(tfd, "dir3", 0755));

        search1 = strjoina(t, "/dir1/");
        search2 = strjoina(t, "/dir2/");
        search3 = strjoina(t, "/dir3/");

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

        ASSERT_OK(touch(strjoina(t2, "/absolute-empty.conf")));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/absolute-empty.conf"), AT_FDCWD, strjoina(search3, "absolute-empty.conf"), /* flags = */ 0));

        ASSERT_OK(write_string_file_at(tfd2, "absolute-non-empty.conf", "absolute-non-empty", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/absolute-non-empty.conf"), AT_FDCWD, strjoina(search3, "absolute-non-empty.conf"), /* flags = */ 0));

        ASSERT_OK(touch(strjoina(t2, "/relative-empty.conf")));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/relative-empty.conf"), AT_FDCWD, strjoina(search3, "relative-empty.conf"), SYMLINK_MAKE_RELATIVE));

        ASSERT_OK(write_string_file_at(tfd2, "relative-non-empty.conf", "relative-non-empty", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/relative-non-empty.conf"), AT_FDCWD, strjoina(search3, "relative-non-empty.conf"), SYMLINK_MAKE_RELATIVE));

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

        /* search dir3 */
        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, CONF_FILES_FILTER_MASKED, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, CONF_FILES_FILTER_MASKED_BY_EMPTY, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, CONF_FILES_FILTER_MASKED_BY_SYMLINK, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"), strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, /* flags = */ 0, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"), strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, CONF_FILES_FILTER_MASKED, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, CONF_FILES_FILTER_MASKED_BY_EMPTY, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, CONF_FILES_FILTER_MASKED_BY_SYMLINK, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, /* flags = */ 0, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED_BY_EMPTY, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED_BY_SYMLINK, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"), strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, /* flags = */ 0, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"), strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"), strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, CONF_FILES_FILTER_MASKED, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, CONF_FILES_FILTER_MASKED_BY_EMPTY, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, CONF_FILES_FILTER_MASKED_BY_SYMLINK, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, /* flags = */ 0, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_isempty(result));
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

static void test_conf_files_insert_one(const char *tmp, const char *root) {
        _cleanup_strv_free_ char **s = NULL;

        log_info("/* %s root=%s */", __func__, strempty(root));

        _cleanup_free_ char *prefix = strdup(path_startswith_full(tmp, empty_to_root(root), PATH_STARTSWITH_RETURN_LEADING_SLASH) ?: "");

        char **dirs = STRV_MAKE(strjoina(prefix, "/dir1"),
                                strjoina(prefix, "/dir2"),
                                strjoina(prefix, "/dir3"),
                                strjoina(prefix, "/dir4"));

        _cleanup_free_ char
                *foo1 = path_join(tmp, "/dir1/foo.conf"),
                *foo2 = path_join(tmp, "/dir2/foo.conf"),
                *bar2 = path_join(tmp, "/dir2/bar.conf"),
                *zzz3 = path_join(tmp, "/dir3/zzz.conf"),
                *whatever = path_join(tmp, "/whatever.conf");

        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir2/foo.conf"), /* ret_inserted = */ NULL));
        strv_print(s);
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(foo2)));

        /* The same file again, https://github.com/systemd/systemd/issues/11124 */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir2/foo.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(foo2)));

        /* Lower priority → new entry is ignored */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir3/foo.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(foo2)));

        /* Higher priority → new entry replaces */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir1/foo.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(foo1)));

        /* Earlier basename */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir2/bar.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(bar2, foo1)));

        /* Later basename */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir3/zzz.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(bar2, foo1, zzz3)));

        /* All lower priority → all ignored */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir3/zzz.conf"), /* ret_inserted = */ NULL));
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir2/bar.conf"), /* ret_inserted = */ NULL));
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir3/bar.conf"), /* ret_inserted = */ NULL));
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir2/foo.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(bar2, foo1, zzz3)));

        /* Two entries that don't match any of the directories, but match basename */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/dir4/zzz.conf"), /* ret_inserted = */ NULL));
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/zzz.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(bar2, foo1, zzz3)));

        /* An entry that doesn't match any of the directories, no match at all */
        ASSERT_OK(conf_files_insert(&s, root, dirs, strjoina(prefix, "/whatever.conf"), /* ret_inserted = */ NULL));
        ASSERT_TRUE(strv_equal(s, STRV_MAKE(bar2, foo1, whatever, zzz3)));
}

TEST(conf_files_insert) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        ASSERT_OK(tfd = mkdtemp_open("/tmp/test-conf-files-XXXXXX", O_PATH, &t));

        ASSERT_OK(mkdirat(tfd, "dir1", 0755));
        ASSERT_OK(mkdirat(tfd, "dir2", 0755));
        ASSERT_OK(mkdirat(tfd, "dir3", 0755));
        ASSERT_OK(mkdirat(tfd, "dir4", 0755));

        test_conf_files_insert_one(t, NULL);
        test_conf_files_insert_one(t, t);
        test_conf_files_insert_one(t, strjoina(t, "/"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
