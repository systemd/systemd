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

        dfd = mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &p);
        assert(dfd >= 0);

        sub_dfd = open_mkdir_at(dfd, "foo.v", O_CLOEXEC, 0777);
        assert(sub_dfd >= 0);

        assert_se(write_string_file_at(sub_dfd, "foo_5.5.raw", "5.5", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_55.raw", "55", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_5.raw", "5", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_5_ia64.raw", "5", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_7.raw", "7", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_7_x86-64.raw", "7 64bit", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_55_x86-64.raw", "55 64bit", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_55_x86.raw", "55 32bit", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_99_x86.raw", "99 32bit", WRITE_STRING_FILE_CREATE) >= 0);

        /* Let's add an entry for sparc (which is a valid arch, but almost certainly not what we test
         * on). This entry should hence always be ignored */
        if (native_architecture() != ARCHITECTURE_SPARC)
                assert_se(write_string_file_at(sub_dfd, "foo_100_sparc.raw", "100 sparc", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(write_string_file_at(sub_dfd, "quux_1_s390.raw", "waldo1", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "quux_2_s390+4-6.raw", "waldo2", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "quux_3_s390+0-10.raw", "waldo3", WRITE_STRING_FILE_CREATE) >= 0);

        _cleanup_free_ char *pp = NULL;
        pp = path_join(p, "foo.v");
        assert_se(pp);

        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

        PickFilter filter = {
                .architecture = _ARCHITECTURE_INVALID,
                .suffix = STRV_MAKE(".raw"),
        };

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
                assert_se(S_ISREG(result.st.st_mode));
                ASSERT_STREQ(result.version, "99");
                assert_se(result.architecture == ARCHITECTURE_X86);
                assert_se(endswith(result.path, "/foo_99_x86.raw"));

                pick_result_done(&result);
        }

        filter.architecture = ARCHITECTURE_X86_64;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        assert_se(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "55");
        assert_se(result.architecture == ARCHITECTURE_X86_64);
        assert_se(endswith(result.path, "/foo_55_x86-64.raw"));
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_IA64;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        assert_se(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        assert_se(result.architecture == ARCHITECTURE_IA64);
        assert_se(endswith(result.path, "/foo_5_ia64.raw"));
        pick_result_done(&result);

        filter.architecture = _ARCHITECTURE_INVALID;
        filter.version = "5";
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        assert_se(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        if (native_architecture() != ARCHITECTURE_IA64) {
                assert_se(result.architecture == _ARCHITECTURE_INVALID);
                assert_se(endswith(result.path, "/foo_5.raw"));
        }
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_IA64;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        assert_se(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        assert_se(result.architecture == ARCHITECTURE_IA64);
        assert_se(endswith(result.path, "/foo_5_ia64.raw"));
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_CRIS;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) == 0);
        assert_se(result.st.st_mode == MODE_INVALID);
        assert_se(!result.version);
        assert_se(result.architecture < 0);
        assert_se(!result.path);

        assert_se(unlinkat(sub_dfd, "foo_99_x86.raw", 0) >= 0);

        filter.architecture = _ARCHITECTURE_INVALID;
        filter.version = NULL;
        if (IN_SET(native_architecture(), ARCHITECTURE_X86_64, ARCHITECTURE_X86)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
                assert_se(S_ISREG(result.st.st_mode));
                ASSERT_STREQ(result.version, "55");

                if (native_architecture() == ARCHITECTURE_X86_64) {
                        assert_se(result.architecture == ARCHITECTURE_X86_64);
                        assert_se(endswith(result.path, "/foo_55_x86-64.raw"));
                } else {
                        assert_se(result.architecture == ARCHITECTURE_X86);
                        assert_se(endswith(result.path, "/foo_55_x86.raw"));
                }
                pick_result_done(&result);
        }

        /* Test explicit patterns in last component of path not being .v */
        free(pp);
        pp = path_join(p, "foo.v/foo___.raw");
        assert_se(pp);

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
                assert_se(S_ISREG(result.st.st_mode));
                ASSERT_STREQ(result.version, "55");
                assert_se(result.architecture == native_architecture());
                assert_se(endswith(result.path, ".raw"));
                assert_se(strrstr(result.path, "/foo_55_x86"));
                pick_result_done(&result);
        }

        /* Specify an explicit path */
        free(pp);
        pp = path_join(p, "foo.v/foo_5.raw");
        assert_se(pp);

        filter.type_mask = UINT32_C(1) << DT_DIR;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) == -ENOTDIR);

        filter.type_mask = UINT32_C(1) << DT_REG;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        assert_se(S_ISREG(result.st.st_mode));
        assert_se(!result.version);
        assert_se(result.architecture == _ARCHITECTURE_INVALID);
        assert_se(path_equal(result.path, pp));
        pick_result_done(&result);

        free(pp);
        pp = path_join(p, "foo.v");
        assert_se(pp);

        filter.architecture = ARCHITECTURE_S390;
        filter.basename = "quux";

        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        assert_se(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "2");
        assert_se(result.tries_left == 4);
        assert_se(result.tries_done == 6);
        assert_se(endswith(result.path, "quux_2_s390+4-6.raw"));
        assert_se(result.architecture == ARCHITECTURE_S390);
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
        _cleanup_close_ int sub_dfd = ASSERT_OK(open_mkdir_at(dfd, "test.raw.v", O_CLOEXEC, 0777));

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
        ASSERT_OK(write_string_file_at(sub_dfd, "test_12", "version 12 no suffix", WRITE_STRING_FILE_CREATE));

        _cleanup_free_ char *pp = ASSERT_NOT_NULL(path_join(p, "test.raw.v"));
        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

        /* Test pick_filter_image_any: should pick the highest version, which is the directory test_5 */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &pick_filter_image_any, PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISDIR(result.st.st_mode));
        ASSERT_STREQ(result.version, "5");
        ASSERT_TRUE(endswith(result.path, "/test_5"));
        pick_result_done(&result);

        /* Remove directories, now it should pick the highest .raw file (test_3.raw) */
        ASSERT_OK(unlinkat(sub_dfd, "test_4", AT_REMOVEDIR));
        ASSERT_OK(unlinkat(sub_dfd, "test_5", AT_REMOVEDIR));

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &pick_filter_image_any, PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_STREQ(result.version, "3");
        ASSERT_TRUE(endswith(result.path, "/test_3.raw"));
        pick_result_done(&result);

        /* Verify that pick_filter_image_raw only matches .raw files */
        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &pick_filter_image_raw, PICK_ARCHITECTURE, &result));
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
        ASSERT_OK_ZERO(path_pick(NULL, AT_FDCWD, pp, &pick_filter_image_any, PICK_ARCHITECTURE, &result));

        /* But if we add a directory, it should be picked */
        ASSERT_OK(mkdirat(sub_dfd, "test_6", 0755));

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &pick_filter_image_any, PICK_ARCHITECTURE, &result));
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

        ASSERT_OK_POSITIVE(path_pick(NULL, AT_FDCWD, pp, &pick_filter_image_dir, PICK_ARCHITECTURE, &result));
        ASSERT_TRUE(S_ISDIR(result.st.st_mode));
        ASSERT_STREQ(result.version, "2");
        ASSERT_TRUE(endswith(result.path, "/myimage_2"));
        pick_result_done(&result);

        /* With no directories, pick_filter_image_dir should return nothing */
        ASSERT_OK(unlinkat(sub_dfd, "myimage_1", AT_REMOVEDIR));
        ASSERT_OK(unlinkat(sub_dfd, "myimage_2", AT_REMOVEDIR));

        ASSERT_OK_ZERO(path_pick(NULL, AT_FDCWD, pp, &pick_filter_image_dir, PICK_ARCHITECTURE, &result));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
