/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
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
        pp = path_join(p, "foo.v");
        ASSERT_TRUE(pp);

        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

        PickFilter filter = {
                .architecture = _ARCHITECTURE_INVALID,
                .suffix = ".raw",
        };

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
                ASSERT_TRUE(S_ISREG(result.st.st_mode));
                ASSERT_TRUE(streq_ptr(result.version, "99"));
                assert_se(result.architecture == ARCHITECTURE_X86);
                assert_se(endswith(result.path, "/foo_99_x86.raw"));

                pick_result_done(&result);
        }

        filter.architecture = ARCHITECTURE_X86_64;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_TRUE(streq_ptr(result.version, "55"));
        assert_se(result.architecture == ARCHITECTURE_X86_64);
        assert_se(endswith(result.path, "/foo_55_x86-64.raw"));
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_IA64;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_TRUE(streq_ptr(result.version, "5"));
        assert_se(result.architecture == ARCHITECTURE_IA64);
        assert_se(endswith(result.path, "/foo_5_ia64.raw"));
        pick_result_done(&result);

        filter.architecture = _ARCHITECTURE_INVALID;
        filter.version = "5";
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_TRUE(streq_ptr(result.version, "5"));
        if (native_architecture() != ARCHITECTURE_IA64) {
                assert_se(result.architecture == _ARCHITECTURE_INVALID);
                assert_se(endswith(result.path, "/foo_5.raw"));
        }
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_IA64;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_TRUE(streq_ptr(result.version, "5"));
        assert_se(result.architecture == ARCHITECTURE_IA64);
        assert_se(endswith(result.path, "/foo_5_ia64.raw"));
        pick_result_done(&result);

        filter.architecture = ARCHITECTURE_CRIS;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) == 0);
        assert_se(result.st.st_mode == MODE_INVALID);
        ASSERT_FALSE(result.version);
        ASSERT_LT(result.architecture, 0);
        ASSERT_FALSE(result.path);

        ASSERT_OK(unlinkat(sub_dfd, "foo_99_x86.raw", 0));

        filter.architecture = _ARCHITECTURE_INVALID;
        filter.version = NULL;
        if (IN_SET(native_architecture(), ARCHITECTURE_X86_64, ARCHITECTURE_X86)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
                ASSERT_TRUE(S_ISREG(result.st.st_mode));
                ASSERT_TRUE(streq_ptr(result.version, "55"));

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
        ASSERT_TRUE(pp);

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
                ASSERT_TRUE(S_ISREG(result.st.st_mode));
                ASSERT_TRUE(streq_ptr(result.version, "55"));
                assert_se(result.architecture == native_architecture());
                ASSERT_TRUE(endswith(result.path, ".raw"));
                assert_se(strrstr(result.path, "/foo_55_x86"));
                pick_result_done(&result);
        }

        /* Specify an explicit path */
        free(pp);
        pp = path_join(p, "foo.v/foo_5.raw");
        ASSERT_TRUE(pp);

        filter.type_mask = UINT32_C(1) << DT_DIR;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) == -ENOTDIR);

        filter.type_mask = UINT32_C(1) << DT_REG;
        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_FALSE(result.version);
        assert_se(result.architecture == _ARCHITECTURE_INVALID);
        ASSERT_TRUE(path_equal(result.path, pp));
        pick_result_done(&result);

        free(pp);
        pp = path_join(p, "foo.v");
        ASSERT_TRUE(pp);

        filter.architecture = ARCHITECTURE_S390;
        filter.basename = "quux";

        assert_se(path_pick(NULL, AT_FDCWD, pp, &filter, PICK_ARCHITECTURE|PICK_TRIES, &result) > 0);
        ASSERT_TRUE(S_ISREG(result.st.st_mode));
        ASSERT_TRUE(streq_ptr(result.version, "2"));
        ASSERT_EQ(result.tries_left, 4u);
        ASSERT_EQ(result.tries_done, 6u);
        assert_se(endswith(result.path, "quux_2_s390+4-6.raw"));
        assert_se(result.architecture == ARCHITECTURE_S390);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
