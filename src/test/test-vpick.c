/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "vpick.h"

TEST(path_pick) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        _cleanup_close_ int dfd = -EBADF, sub_dfd = -EBADF;

        dfd = ASSERT_OK(mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &p));
        sub_dfd = ASSERT_OK(open_mkdir_at(dfd, "foo.v", O_CLOEXEC, 0777));

        ASSERT_OK(write_string_file_at(sub_dfd, "foo_5.5.raw", "5.5", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_55.raw", "55", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_5.raw", "5", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_5_ia64.raw", "5", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_7.raw", "7", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_7_x86-64.raw", "7 64bit", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_55_x86-64.raw", "55 64bit", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_55_x86.raw", "55 32bit", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "foo_99_x86.raw", "99 32bit", WRITE_STRING_FILE_CREATE));

        /* Let's add an entry for sparc (which is a valid arch, but almost certainly not what we test
         * on). This entry should hence always be ignored */
        if (native_architecture() != ARCHITECTURE_SPARC)
                ASSERT_OK(write_string_file_at(sub_dfd, "foo_100_sparc.raw", "100 sparc", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(write_string_file_at(sub_dfd, "quux_1_s390.raw", "waldo1", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "quux_2_s390+4-6.raw", "waldo2", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "quux_3_s390+0-10.raw", "waldo3", WRITE_STRING_FILE_CREATE));

        _cleanup_free_ char *pp = NULL;
        pp = ASSERT_NOT_NULL(path_join(p, "foo.v"));

        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

        PickFilter filter = {
                .architecture = _ARCHITECTURE_INVALID,
                .suffix = ".raw",
        };

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
                ASSERT_TRUE(S_ISREG(result.st.st_mode));
                ASSERT_STREQ(result.version, "99");
                ASSERT_EQ(result.architecture, ARCHITECTURE_X86);
                ASSERT_TRUE(endswith(result.path, "/foo_99_x86.raw"));

                pick_result_done(&result);
        }

        filter.architecture = ARCHITECTURE_X86_64;
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "55");
        ASSERT_EQ(result.architecture, ARCHITECTURE_X86_64);
        ASSERT_TRUE(endswith(result.path, "/foo_55_x86-64.raw"));
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_IA64;
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        ASSERT_EQ(result.architecture, ARCHITECTURE_IA64);
        ASSERT_TRUE(endswith(result.path, "/foo_5_ia64.raw"));
        pick_result_done(&result);

        filter.architecture = _ARCHITECTURE_INVALID;
        filter.version = "5";
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        if (native_architecture() != ARCHITECTURE_IA64) {
                ASSERT_EQ(result.architecture, _ARCHITECTURE_INVALID);
                ASSERT_TRUE(endswith(result.path, "/foo_5.raw"));
        }
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_IA64;
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        ASSERT_EQ(result.architecture, ARCHITECTURE_IA64);
        ASSERT_TRUE(endswith(result.path, "/foo_5_ia64.raw"));
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_CRIS;
        ASSERT_OK_ZERO(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
        ASSERT_EQ(result.st.st_mode, MODE_INVALID);
        ASSERT_NULL(result.version);
        ASSERT_LT(result.architecture, 0);
        ASSERT_NULL(result.path);

        ASSERT_OK_ERRNO(unlinkat(sub_dfd, "foo_99_x86.raw", 0));

        filter.architecture = _ARCHITECTURE_INVALID;
        filter.version = NULL;
        if (IN_SET(native_architecture(), ARCHITECTURE_X86_64, ARCHITECTURE_X86)) {
                ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
                ASSERT_TRUE(S_ISREG(result.st.st_mode));
                ASSERT_STREQ(result.version, "55");

                if (native_architecture() == ARCHITECTURE_X86_64) {
                        ASSERT_EQ(result.architecture, ARCHITECTURE_X86_64);
                        ASSERT_TRUE(endswith(result.path, "/foo_55_x86-64.raw"));
                } else {
                        ASSERT_EQ(result.architecture, ARCHITECTURE_X86);
                        ASSERT_TRUE(endswith(result.path, "/foo_55_x86.raw"));
                }
                pick_result_done(&result);
        }

        /* Test explicit patterns in last component of path not being .v */
        free(pp);
        pp = ASSERT_NOT_NULL(path_join(p, "foo.v/foo___.raw"));

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
                ASSERT_TRUE(S_ISREG(result.st.st_mode));
                ASSERT_STREQ(result.version, "55");
                ASSERT_EQ(result.architecture, native_architecture());
                ASSERT_TRUE(endswith(result.path, ".raw"));
                ASSERT_TRUE(!!strrstr(result.path, "/foo_55_x86"));
                pick_result_done(&result);
        }

        /* Specify an explicit path */
        free(pp);
        pp = ASSERT_NOT_NULL(path_join(p, "foo.v/foo_5.raw"));

        filter.type_mask = UINT32_C(1) << DT_DIR;
        ASSERT_OK_ZERO(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));

        filter.type_mask = UINT32_C(1) << DT_REG;
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_NULL(result.version);
        ASSERT_EQ(result.architecture, _ARCHITECTURE_INVALID);
        ASSERT_TRUE(path_equal(result.path, pp));
        pick_result_done(&result);

        free(pp);
        pp = ASSERT_NOT_NULL(path_join(p, "foo.v"));

        filter.architecture = ARCHITECTURE_S390;
        filter.basename = "quux";

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE|PICK_TRIES, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "2");
        ASSERT_EQ(result.tries_left, 4U);
        ASSERT_EQ(result.tries_done, 6U);
        ASSERT_TRUE(endswith(result.path, "quux_2_s390+4-6.raw"));
        ASSERT_EQ(result.architecture, ARCHITECTURE_S390);
}

TEST(path_uses_vpick) {
        ASSERT_OK_POSITIVE(path_uses_vpick("foo.v"));
        ASSERT_OK_POSITIVE(path_uses_vpick("path/to/foo.v"));
        ASSERT_OK_POSITIVE(path_uses_vpick("./path/to/foo.v"));
        ASSERT_OK_POSITIVE(path_uses_vpick("path/to.v/foo.v"));
        ASSERT_OK_POSITIVE(path_uses_vpick("path/to/foo.raw.v"));
        ASSERT_OK_POSITIVE(path_uses_vpick("/var/lib/machines/mymachine.raw.v/"));
        ASSERT_OK_POSITIVE(path_uses_vpick("path/to.v/foo___.hi/a.v"));
        ASSERT_OK_ZERO(path_uses_vpick("path/to/foo.mp4.vtt"));
        ASSERT_OK_ZERO(path_uses_vpick("path/to/foo.mp4.v.1"));
        ASSERT_OK_ZERO(path_uses_vpick("path/to.v/a"));

        ASSERT_OK_POSITIVE(path_uses_vpick("to.v/foo___.raw"));
        ASSERT_OK_POSITIVE(path_uses_vpick("path/to.v/foo___.raw"));
        ASSERT_OK_ZERO(path_uses_vpick("path/to/foo___.raw"));
        ASSERT_OK_ZERO(path_uses_vpick("path/to.v/foo__"));
        ASSERT_OK_ZERO(path_uses_vpick("foo___.raw"));

        ASSERT_OK_ZERO(path_uses_vpick("/"));
        ASSERT_OK_ZERO(path_uses_vpick("."));
        ASSERT_ERROR(path_uses_vpick(""), EINVAL);
}

TEST(pick_filter_image_any) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;

        _cleanup_close_ int dfd = ASSERT_OK(mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &p));
        _cleanup_close_ int sub_dfd = ASSERT_OK(open_mkdir_at(dfd, "test.v", O_CLOEXEC, 0777));

        /* Create .raw files (should match with pick_filter_image_raw and pick_filter_image_any) */
        ASSERT_OK(write_string_file_at(sub_dfd, "test_1.raw", "version 1 raw", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "test_2.raw", "version 2 raw", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "test_3.raw", "version 3 raw", WRITE_STRING_FILE_CREATE));

        /* Create directories (should match with pick_filter_image_dir and pick_filter_image_any) */
        ASSERT_OK(mkdirat(sub_dfd, "test_4", 0755));
        ASSERT_OK(mkdirat(sub_dfd, "test_5", 0755));

        /* Create files without .raw suffix (should NOT match any of the pick_filter_image_* filters) */
        ASSERT_OK(write_string_file_at(sub_dfd, "test_10.txt", "version 10 txt", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "test_11.img", "version 11 img", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(sub_dfd, "test_12", "version 12", WRITE_STRING_FILE_CREATE));

        _cleanup_free_ char *pp = ASSERT_NOT_NULL(path_join(p, "test.v"));
        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

        /* Test pick_filter_image_any: should pick the highest version, which is the directory test_5 */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_any, ELEMENTSOF(pick_filter_image_any), PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISDIR(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        ASSERT_TRUE(endswith(result.path, "/test_5"));
        pick_result_done(&result);

        /* Remove directories, now it should pick the highest .raw file (test_3.raw) */
        ASSERT_OK(unlinkat(sub_dfd, "test_4", AT_REMOVEDIR));
        ASSERT_OK(unlinkat(sub_dfd, "test_5", AT_REMOVEDIR));

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_any, ELEMENTSOF(pick_filter_image_any), PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "3");
        ASSERT_TRUE(endswith(result.path, "/test_3.raw"));
        pick_result_done(&result);

        /* Verify that pick_filter_image_raw only matches .raw files */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_raw, ELEMENTSOF(pick_filter_image_raw), PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "3");
        ASSERT_TRUE(endswith(result.path, "/test_3.raw"));
        pick_result_done(&result);

        /* Verify that files without .raw suffix are never picked by pick_filter_image_any */
        /* Remove all .raw files */
        ASSERT_OK(unlinkat(sub_dfd, "test_1.raw", 0));
        ASSERT_OK(unlinkat(sub_dfd, "test_2.raw", 0));
        ASSERT_OK(unlinkat(sub_dfd, "test_3.raw", 0));

        /* Now only test_10.txt, test_11.img, and test_12 remain - none should match */
        ASSERT_OK_ZERO(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_any, ELEMENTSOF(pick_filter_image_any), PICK_ARCHITECTURE, &result));

        /* But if we add a directory, it should be picked */
        ASSERT_OK(mkdirat(sub_dfd, "test_6", 0755));

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_any, ELEMENTSOF(pick_filter_image_any), PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISDIR(result.st.st_mode));
        ASSERT_STREQ(result.version, "6");
        ASSERT_TRUE(endswith(result.path, "/test_6"));
        pick_result_done(&result);

        /* Now test pick_filter_image_dir with a separate directory structure */
        safe_close(sub_dfd);
        sub_dfd = ASSERT_OK(open_mkdir_at(dfd, "myimage.v", O_CLOEXEC, 0777));

        /* Create directories that pick_filter_image_dir should find */
        ASSERT_OK(mkdirat(sub_dfd, "myimage_1", 0755));
        ASSERT_OK(mkdirat(sub_dfd, "myimage_2", 0755));

        free(pp);
        pp = ASSERT_NOT_NULL(path_join(p, "myimage.v"));

        pick_result_done(&result);

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_dir, ELEMENTSOF(pick_filter_image_dir), PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISDIR(result.st.st_mode));
        ASSERT_STREQ(result.version, "2");
        ASSERT_TRUE(endswith(result.path, "/myimage_2"));
        pick_result_done(&result);

        /* With no directories, pick_filter_image_dir should return nothing */
        ASSERT_OK(unlinkat(sub_dfd, "myimage_1", AT_REMOVEDIR));
        ASSERT_OK(unlinkat(sub_dfd, "myimage_2", AT_REMOVEDIR));

        ASSERT_OK_ZERO(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_dir, ELEMENTSOF(pick_filter_image_dir), PICK_ARCHITECTURE, &result));
}

TEST(path_pick_resolve) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;

        _cleanup_close_ int dfd = ASSERT_OK(mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &p));
        _cleanup_close_ int sub_dfd = ASSERT_OK(open_mkdir_at(dfd, "resolve.v", O_CLOEXEC, 0777));

        /* Create a target directory and file for symlinks */
        ASSERT_OK(mkdirat(dfd, "target_dir", 0755));
        ASSERT_OK(write_string_file_at(dfd, "target_file.raw", "target content", WRITE_STRING_FILE_CREATE));

        /* Create symlinks inside the .v directory pointing to targets outside */
        ASSERT_OK(symlinkat("../target_dir", sub_dfd, "resolve_1"));
        ASSERT_OK(symlinkat("../target_file.raw", sub_dfd, "resolve_2.raw"));

        _cleanup_free_ char *pp = ASSERT_NOT_NULL(path_join(p, "resolve.v"));
        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

        /* Test without PICK_RESOLVE - should return the symlink path */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_any, ELEMENTSOF(pick_filter_image_any), PICK_ARCHITECTURE, &result));
        ASSERT_STREQ(result.version, "2");
        ASSERT_TRUE(endswith(result.path, "/resolve_2.raw"));
        pick_result_done(&result);

        /* Test with PICK_RESOLVE - should return the resolved (target) path */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_any, ELEMENTSOF(pick_filter_image_any), PICK_ARCHITECTURE|PICK_RESOLVE, &result));
        ASSERT_STREQ(result.version, "2");
        ASSERT_TRUE(endswith(result.path, "/target_file.raw"));
        pick_result_done(&result);

        /* Test pick_filter_image_dir without PICK_RESOLVE */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_dir, ELEMENTSOF(pick_filter_image_dir), PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISDIR(result.st.st_mode));
        ASSERT_STREQ(result.version, "1");
        ASSERT_TRUE(endswith(result.path, "/resolve_1"));
        pick_result_done(&result);

        /* Test pick_filter_image_dir with PICK_RESOLVE */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_dir, ELEMENTSOF(pick_filter_image_dir), PICK_ARCHITECTURE|PICK_RESOLVE, &result));
        ASSERT_TRUE(S_ISDIR(result.st.st_mode));
        ASSERT_STREQ(result.version, "1");
        ASSERT_TRUE(endswith(result.path, "/target_dir"));
        pick_result_done(&result);

        /* Test with a chain of symlinks */
        ASSERT_OK(symlinkat("target_file.raw", dfd, "intermediate_link.raw"));
        ASSERT_OK(symlinkat("../intermediate_link.raw", sub_dfd, "resolve_3.raw"));

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_raw, ELEMENTSOF(pick_filter_image_raw), PICK_ARCHITECTURE, &result));
        ASSERT_STREQ(result.version, "3");
        ASSERT_TRUE(endswith(result.path, "/resolve_3.raw"));
        pick_result_done(&result);

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, pick_filter_image_raw, ELEMENTSOF(pick_filter_image_raw), PICK_ARCHITECTURE|PICK_RESOLVE, &result));
        ASSERT_STREQ(result.version, "3");
        /* The chain should be fully resolved to target_file.raw */
        ASSERT_TRUE(endswith(result.path, "/target_file.raw"));
        pick_result_done(&result);
}

TEST(pick_result_compare) {
        PickResult a = PICK_RESULT_NULL, b = PICK_RESULT_NULL;

        /* When everything is equal, compare paths */
        a.path = (char*) "/a";
        b.path = (char*) "/b";
        ASSERT_LT(pick_result_compare(&a, &b, 0), 0);
        ASSERT_GT(pick_result_compare(&b, &a, 0), 0);
        ASSERT_EQ(pick_result_compare(&a, &a, 0), 0);

        /* Prefer newer versions */
        a.version = (char*) "1";
        b.version = (char*) "2";
        ASSERT_LT(pick_result_compare(&a, &b, 0), 0);
        ASSERT_GT(pick_result_compare(&b, &a, 0), 0);
        a.version = b.version = NULL;

        /* Prefer entries with tries left over those without (only with PICK_TRIES) */
        a.tries_left = 0;
        b.tries_left = 1;
        ASSERT_LT(pick_result_compare(&a, &b, 0), 0); /* Without PICK_TRIES, paths are compared */
        ASSERT_LT(pick_result_compare(&a, &b, PICK_TRIES), 0);
        ASSERT_GT(pick_result_compare(&b, &a, PICK_TRIES), 0);

        /* Prefer entries with more tries left */
        a.tries_left = 1;
        b.tries_left = 5;
        ASSERT_LT(pick_result_compare(&a, &b, PICK_TRIES), 0);
        ASSERT_GT(pick_result_compare(&b, &a, PICK_TRIES), 0);

        /* Prefer entries with fewer attempts done */
        a.tries_left = b.tries_left = 3;
        a.tries_done = 5;
        b.tries_done = 1;
        ASSERT_LT(pick_result_compare(&a, &b, PICK_TRIES), 0);
        ASSERT_GT(pick_result_compare(&b, &a, PICK_TRIES), 0);
        a.tries_left = b.tries_left = UINT_MAX;
        a.tries_done = b.tries_done = UINT_MAX;

        /* Prefer native architecture (only with PICK_ARCHITECTURE) */
        a.architecture = native_architecture();
        b.architecture = ARCHITECTURE_ALPHA; /* Unlikely to be native */
        if (native_architecture() != ARCHITECTURE_ALPHA) {
                ASSERT_LT(pick_result_compare(&a, &b, 0), 0); /* Without PICK_ARCHITECTURE, paths are compared */
                ASSERT_GT(pick_result_compare(&a, &b, PICK_ARCHITECTURE), 0);
                ASSERT_LT(pick_result_compare(&b, &a, PICK_ARCHITECTURE), 0);
        }
        a.architecture = b.architecture = _ARCHITECTURE_INVALID;

        /* Version takes precedence over architecture */
        a.version = (char*) "1";
        b.version = (char*) "2";
        a.architecture = native_architecture();
        b.architecture = ARCHITECTURE_ALPHA;
        if (native_architecture() != ARCHITECTURE_ALPHA)
                ASSERT_LT(pick_result_compare(&a, &b, PICK_ARCHITECTURE), 0); /* b wins due to higher version */
        a.version = b.version = NULL;
        a.architecture = b.architecture = _ARCHITECTURE_INVALID;

        /* Tries left takes precedence over version */
        a.tries_left = 0;
        b.tries_left = 1;
        a.version = (char*) "2";
        b.version = (char*) "1";
        ASSERT_LT(pick_result_compare(&a, &b, PICK_TRIES), 0); /* b wins due to tries left */
        a.tries_left = b.tries_left = UINT_MAX;
        a.version = b.version = NULL;
}

DEFINE_TEST_MAIN(LOG_DEBUG);
