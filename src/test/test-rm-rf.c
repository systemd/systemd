/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "capability-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_rm_rf_chmod_inner(void) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        const char *a, *b, *x, *y;
        struct stat st;

        ASSERT_NE(getuid(), 0U);

        ASSERT_OK(mkdtemp_malloc("/tmp/test-rm-rf.XXXXXXX", &d));
        a = strjoina(d, "/a");
        b = strjoina(a, "/b");
        x = strjoina(d, "/x");
        y = strjoina(x, "/y");

        ASSERT_OK_ERRNO(mkdir(x, 0700));
        ASSERT_OK_ERRNO(mknod(y, S_IFREG | 0600, 0));

        ASSERT_OK_ERRNO(chmod(y, 0400));
        ASSERT_OK_ERRNO(chmod(x, 0500));
        ASSERT_OK_ERRNO(chmod(d, 0500));

        if (!have_effective_cap(CAP_DAC_OVERRIDE))
                ASSERT_ERROR(rm_rf(d, REMOVE_PHYSICAL), EACCES);

        ASSERT_OK_ERRNO(access(d, F_OK));
        ASSERT_OK_ERRNO(access(x, F_OK));
        ASSERT_OK_ERRNO(access(y, F_OK));

        ASSERT_OK(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD));

        ASSERT_OK_ERRNO(access(d, F_OK));
        ASSERT_ERROR_ERRNO(access(x, F_OK), ENOENT);
        ASSERT_ERROR_ERRNO(access(y, F_OK), ENOENT);

        ASSERT_OK_ERRNO(mkdir(a, 0700));
        ASSERT_OK_ERRNO(mkdir(b, 0700));
        ASSERT_OK_ERRNO(mkdir(x, 0700));
        ASSERT_OK_ERRNO(mknod(y, S_IFREG | 0600, 0));

        ASSERT_OK_ERRNO(chmod(b, 0000));
        ASSERT_OK_ERRNO(chmod(a, 0000));
        ASSERT_OK_ERRNO(chmod(y, 0000));
        ASSERT_OK_ERRNO(chmod(x, 0000));
        ASSERT_OK_ERRNO(chmod(d, 0500));

        ASSERT_ERROR(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_CHMOD_RESTORE|REMOVE_ONLY_DIRECTORIES), ENOTEMPTY);

        ASSERT_ERROR_ERRNO(access(a, F_OK), ENOENT);
        ASSERT_OK_ERRNO(access(d, F_OK));
        ASSERT_OK_ERRNO(stat(d, &st));
        ASSERT_EQ(st.st_mode & 07777, 0500U);
        ASSERT_OK_ERRNO(access(x, F_OK));
        ASSERT_OK_ERRNO(stat(x, &st));
        ASSERT_EQ(st.st_mode & 07777, 0000U);
        ASSERT_OK_ERRNO(chmod(x, 0700));
        ASSERT_OK_ERRNO(access(y, F_OK));
        ASSERT_OK_ERRNO(stat(y, &st));
        ASSERT_EQ(st.st_mode & 07777, 0000U);

        ASSERT_OK_ERRNO(chmod(y, 0000));
        ASSERT_OK_ERRNO(chmod(x, 0000));
        ASSERT_OK_ERRNO(chmod(d, 0000));

        ASSERT_OK(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_CHMOD_RESTORE));

        ASSERT_OK_ERRNO(stat(d, &st));
        ASSERT_EQ(st.st_mode & 07777, 0000U);
        ASSERT_OK_ERRNO(access(d, F_OK));
        ASSERT_OK_ERRNO(chmod(d, 0700));
        ASSERT_ERROR_ERRNO(access(x, F_OK), ENOENT);

        ASSERT_OK_ERRNO(mkdir(x, 0700));
        ASSERT_OK_ERRNO(mknod(y, S_IFREG | 0600, 0));

        ASSERT_OK_ERRNO(chmod(y, 0000));
        ASSERT_OK_ERRNO(chmod(x, 0000));
        ASSERT_OK_ERRNO(chmod(d, 0000));

        ASSERT_OK(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_ROOT));

        ASSERT_ERROR_ERRNO(access(d, F_OK), ENOENT);
}

TEST(rm_rf_chmod) {
        int r;

        if (getuid() == 0 && userns_has_single_user())
                return (void) log_tests_skipped("running as root or in userns with single user");

        if (getuid() == 0) {
                /* This test only works unpriv (as only then the access mask for the owning user matters),
                 * hence drop privs here */

                ASSERT_OK(r = safe_fork("(setresuid)", FORK_DEATHSIG_SIGTERM|FORK_WAIT, NULL));

                if (r == 0) {
                        /* child */

                        ASSERT_OK_ERRNO(setresuid(1, 1, 1));

                        test_rm_rf_chmod_inner();
                        _exit(EXIT_SUCCESS);
                }

                return;
        }

        test_rm_rf_chmod_inner();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
