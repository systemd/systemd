/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Michael Marineau
***/

#include <sys/stat.h>
#include <unistd.h>

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
        const char *search1, *search2, *search3, *search1_a, *search1_b, *search1_c, *search2_aa, *search2_mm;

        ASSERT_OK(tfd = mkdtemp_open("/tmp/test-conf-files-XXXXXX", O_PATH, &t));
        ASSERT_OK(tfd2 = mkdtemp_open("/tmp/test-conf-files-XXXXXX", O_PATH, &t2));

        ASSERT_OK_ERRNO(mkdirat(tfd, "dir1", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "dir2", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "dir3", 0755));

        search1 = strjoina(t, "/dir1/");
        search2 = strjoina(t, "/dir2/");
        search3 = strjoina(t, "/dir3/");

        FOREACH_STRING(p, "a.conf", "b.conf", "c.foo") {
                _cleanup_free_ char *path = NULL;

                ASSERT_NOT_NULL(path = path_join(search1, p));
                ASSERT_OK(write_string_file(path, "foobar", WRITE_STRING_FILE_CREATE));
        }

        ASSERT_OK_ERRNO(symlinkat("/dev/null", tfd, "dir1/m.conf"));
        ASSERT_OK_ERRNO(symlinkat("../dev/null", tfd, "dir1/mm.conf"));

        FOREACH_STRING(p, "a.conf", "aa.conf", "m.conf", "mm.conf") {
                _cleanup_free_ char *path = NULL;

                ASSERT_NOT_NULL(path = path_join(search2, p));
                ASSERT_OK(write_string_file(path, "hogehoge", WRITE_STRING_FILE_CREATE));
        }

        ASSERT_OK(touch(strjoina(t2, "/absolute-empty.real")));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/absolute-empty.real"), AT_FDCWD, strjoina(search3, "absolute-empty.conf"), /* flags = */ 0));

        ASSERT_OK(write_string_file_at(tfd2, "absolute-non-empty.real", "absolute-non-empty", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/absolute-non-empty.real"), AT_FDCWD, strjoina(search3, "absolute-non-empty.conf"), /* flags = */ 0));

        ASSERT_OK(touch(strjoina(t2, "/relative-empty.real")));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/relative-empty.real"), AT_FDCWD, strjoina(search3, "relative-empty.conf"), SYMLINK_MAKE_RELATIVE));

        ASSERT_OK(write_string_file_at(tfd2, "relative-non-empty.real", "relative-non-empty", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(symlinkat_atomic_full(strjoina(t2, "/relative-non-empty.real"), AT_FDCWD, strjoina(search3, "relative-non-empty.conf"), SYMLINK_MAKE_RELATIVE));

        ASSERT_OK(touch(strjoina(t, "/absolute-empty-for-root.real")));
        ASSERT_OK(symlinkat_atomic_full("/absolute-empty-for-root.real", AT_FDCWD, strjoina(search3, "absolute-empty-for-root.conf"), /* flags = */ 0));

        ASSERT_OK(write_string_file_at(tfd, "absolute-non-empty-for-root.real", "absolute-non-empty", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(symlinkat_atomic_full("/absolute-non-empty-for-root.real", AT_FDCWD, strjoina(search3, "absolute-non-empty-for-root.conf"), /* flags = */ 0));

        ASSERT_OK(touch(strjoina(t, "/relative-empty-for-root.real")));
        ASSERT_OK(symlinkat_atomic_full("../../../../relative-empty-for-root.real", AT_FDCWD, strjoina(search3, "relative-empty-for-root.conf"), /* flags = */ 0));

        ASSERT_OK(write_string_file_at(tfd, "relative-non-empty-for-root.real", "relative-non-empty", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(symlinkat_atomic_full("../../../../relative-non-empty-for-root.real", AT_FDCWD, strjoina(search3, "relative-non-empty-for-root.conf"), /* flags = */ 0));

        search1_a = strjoina(search1, "a.conf");
        search1_b = strjoina(search1, "b.conf");
        search1_c = strjoina(search1, "c.foo");
        search2_aa = strjoina(search2, "aa.conf");
        search2_mm = strjoina(search2, "mm.conf");

        /* search dir1 without suffix */
        ASSERT_OK(conf_files_list(&result, NULL, NULL, CONF_FILES_FILTER_MASKED, search1));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, NULL, "/", CONF_FILES_FILTER_MASKED, search1));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, NULL, "///../../././//", CONF_FILES_FILTER_MASKED, search1));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, NULL, t, CONF_FILES_FILTER_MASKED, "/dir1/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED, search1));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, NULL, tfd, CONF_FILES_FILTER_MASKED, "/dir1/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir1/a.conf", "dir1/b.conf", "dir1/c.foo")));

        result = strv_free(result);

        /* search dir1 with relative path */
        ASSERT_OK_ERRNO(chdir("/tmp/"));

        ASSERT_OK(conf_files_list(&result, NULL, NULL, CONF_FILES_FILTER_MASKED, path_startswith(search1, "/tmp/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, NULL, "/", CONF_FILES_FILTER_MASKED, path_startswith(search1, "/tmp/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, NULL, "///../../././//", CONF_FILES_FILTER_MASKED, path_startswith(search1, "/tmp/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, NULL, t, CONF_FILES_FILTER_MASKED, "dir1"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b, search1_c)));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED, path_startswith(search1, "/tmp/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(path_startswith(search1_a, "/tmp/"),
                                                 path_startswith(search1_b, "/tmp/"),
                                                 path_startswith(search1_c, "/tmp/"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, NULL, tfd, CONF_FILES_FILTER_MASKED, "dir1"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir1/a.conf", "dir1/b.conf", "dir1/c.foo")));
        result = strv_free(result);

        /* search dir1 with suffix */
        ASSERT_OK(conf_files_list(&result, ".conf", NULL, CONF_FILES_FILTER_MASKED, search1));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, ".conf", t, CONF_FILES_FILTER_MASKED, "/dir1/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, ".conf", AT_FDCWD, CONF_FILES_FILTER_MASKED, search1));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search1_b)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, ".conf", tfd, CONF_FILES_FILTER_MASKED, "/dir1/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir1/a.conf", "dir1/b.conf")));

        result = strv_free(result);

        /* search two dirs */
        ASSERT_OK(conf_files_list_strv(&result, ".conf", NULL, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST(search1, search2)));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search2_aa, search1_b, search2_mm)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_strv(&result, ".conf", t, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST("/dir1/", "/dir2/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search2_aa, search1_b)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_strv_at(&result, ".conf", AT_FDCWD, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST(search1, search2)));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a, search2_aa, search1_b, search2_mm)));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_strv_at(&result, ".conf", tfd, CONF_FILES_FILTER_MASKED, STRV_MAKE_CONST("/dir1/", "/dir2/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir1/a.conf", "dir2/aa.conf", "dir1/b.conf")));

        result = strv_free(result);

        /* search dir3 */
        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, CONF_FILES_FILTER_MASKED, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, CONF_FILES_FILTER_MASKED_BY_EMPTY, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, CONF_FILES_FILTER_MASKED_BY_SYMLINK, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, /* root = */ NULL, CONF_FILES_REGULAR, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, CONF_FILES_FILTER_MASKED, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, CONF_FILES_FILTER_MASKED_BY_EMPTY, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, CONF_FILES_FILTER_MASKED_BY_SYMLINK, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty-for-root.conf"),
                                                 strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 strjoina(search3, "relative-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list(&result, /* suffix = */ NULL, t, CONF_FILES_REGULAR, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty-for-root.conf"),
                                                 strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 strjoina(search3, "relative-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED_BY_EMPTY, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, CONF_FILES_FILTER_MASKED_BY_SYMLINK, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, AT_FDCWD, CONF_FILES_REGULAR, search3));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, CONF_FILES_FILTER_MASKED, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir3/absolute-non-empty-for-root.conf",
                                                 "dir3/relative-non-empty-for-root.conf")));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, CONF_FILES_FILTER_MASKED_BY_EMPTY, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir3/absolute-non-empty-for-root.conf",
                                                 "dir3/relative-non-empty-for-root.conf")));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, CONF_FILES_FILTER_MASKED_BY_SYMLINK, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir3/absolute-empty-for-root.conf",
                                                 "dir3/absolute-non-empty-for-root.conf",
                                                 "dir3/relative-empty-for-root.conf",
                                                 "dir3/relative-non-empty-for-root.conf")));
        result = strv_free(result);

        ASSERT_OK(conf_files_list_at(&result, /* suffix = */ NULL, tfd, CONF_FILES_REGULAR, "/dir3/"));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("dir3/absolute-empty-for-root.conf",
                                                 "dir3/absolute-non-empty-for-root.conf",
                                                 "dir3/relative-empty-for-root.conf",
                                                 "dir3/relative-non-empty-for-root.conf")));
        result = strv_free(result);

        /* filename only */
        ASSERT_OK(conf_files_list_strv(&result, ".conf", NULL, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST(search1, search2)));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf", "mm.conf")));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_strv(&result, ".conf", t, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST("/dir1/", "/dir2/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf")));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_strv_at(&result, ".conf", AT_FDCWD, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST(search1, search2)));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf", "mm.conf")));

        result = strv_free(result);

        ASSERT_OK(conf_files_list_strv_at(&result, ".conf", tfd, CONF_FILES_FILTER_MASKED | CONF_FILES_BASENAME, STRV_MAKE_CONST("/dir1/", "/dir2/")));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE("a.conf", "aa.conf", "b.conf")));

        result = strv_free(result);

        /* with replacement */
        _cleanup_free_ char *inserted = NULL;
        ASSERT_OK(conf_files_list_with_replacement(/* root = */ NULL, STRV_MAKE(search1, search2, search3), search1_a, &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 search1_b,
                                                 strjoina(search2, "mm.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        ASSERT_STREQ(inserted, search1_a);
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(/* root = */ NULL, STRV_MAKE(search1, search2, search3), strjoina(t, "/dir1/aa.conf"), &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 strjoina(search1, "aa.conf"),
                                                 strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 search1_b,
                                                 strjoina(search2, "mm.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        ASSERT_STREQ(inserted, strjoina(search1, "aa.conf"));
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(/* root = */ NULL, STRV_MAKE(search1, search2, search3), strjoina(t, "/dir2/a.conf"), &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 search1_b,
                                                 strjoina(search2, "mm.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        ASSERT_NULL(inserted);
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(/* root = */ NULL, STRV_MAKE(search1, search2, search3), strjoina(t, "/dir4/a.conf"), &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 search1_b,
                                                 strjoina(search2, "mm.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"))));
        ASSERT_NULL(inserted);
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(/* root = */ NULL, STRV_MAKE(search1, search2, search3), strjoina(t, "/dir4/x.conf"), &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty.conf"),
                                                 strjoina(search3, "absolute-non-empty.conf"),
                                                 search1_b,
                                                 strjoina(search2, "mm.conf"),
                                                 strjoina(search3, "relative-empty.conf"),
                                                 strjoina(search3, "relative-non-empty.conf"),
                                                 strjoina(t, "/dir4/x.conf"))));
        ASSERT_STREQ(inserted, strjoina(t, "/dir4/x.conf"));
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(t, STRV_MAKE("/dir1/", "/dir2/", "/dir3/"), "/dir1/a.conf", &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty-for-root.conf"),
                                                 strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 search1_b,
                                                 strjoina(search3, "relative-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        ASSERT_STREQ(inserted, search1_a);
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(t, STRV_MAKE("/dir1/", "/dir2/", "/dir3/"), "/dir1/aa.conf", &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 strjoina(search1, "aa.conf"),
                                                 strjoina(search3, "absolute-empty-for-root.conf"),
                                                 strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 search1_b,
                                                 strjoina(search3, "relative-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        ASSERT_STREQ(inserted, strjoina(search1, "aa.conf"));
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(t, STRV_MAKE("/dir1/", "/dir2/", "/dir3/"), "/dir2/a.conf", &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty-for-root.conf"),
                                                 strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 search1_b,
                                                 strjoina(search3, "relative-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        ASSERT_NULL(inserted);
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(t, STRV_MAKE("/dir1/", "/dir2/", "/dir3/"), "/dir4/a.conf", &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty-for-root.conf"),
                                                 strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 search1_b,
                                                 strjoina(search3, "relative-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"))));
        ASSERT_NULL(inserted);
        result = strv_free(result);
        inserted = mfree(inserted);

        ASSERT_OK(conf_files_list_with_replacement(t, STRV_MAKE("/dir1/", "/dir2/", "/dir3/"), "/dir4/x.conf", &result, &inserted));
        strv_print(result);
        ASSERT_TRUE(strv_equal(result, STRV_MAKE(search1_a,
                                                 search2_aa,
                                                 strjoina(search3, "absolute-empty-for-root.conf"),
                                                 strjoina(search3, "absolute-non-empty-for-root.conf"),
                                                 search1_b,
                                                 strjoina(search3, "relative-empty-for-root.conf"),
                                                 strjoina(search3, "relative-non-empty-for-root.conf"),
                                                 strjoina(t, "/dir4/x.conf"))));
        ASSERT_STREQ(inserted, strjoina(t, "/dir4/x.conf"));
        result = strv_free(result);
        inserted = mfree(inserted);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
