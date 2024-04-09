/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_rm_rf_chmod_inner(void) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        const char *a, *b, *x, *y;
        struct stat st;

        ASSERT_NE(getuid(), 0u);

        assert_se(mkdtemp_malloc("/tmp/test-rm-rf.XXXXXXX", &d) >= 0);
        a = strjoina(d, "/a");
        b = strjoina(a, "/b");
        x = strjoina(d, "/x");
        y = strjoina(x, "/y");

        ASSERT_OK(mkdir(x, 0700));
        assert_se(mknod(y, S_IFREG | 0600, 0) >= 0);

        ASSERT_OK(chmod(y, 0400));
        ASSERT_OK(chmod(x, 0500));
        ASSERT_OK(chmod(d, 0500));

        assert_se(rm_rf(d, REMOVE_PHYSICAL) == -EACCES);

        ASSERT_OK(access(d, F_OK));
        ASSERT_OK(access(x, F_OK));
        ASSERT_OK(access(y, F_OK));

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD) >= 0);

        ASSERT_OK(access(d, F_OK));
        assert_se(access(x, F_OK) < 0 && errno == ENOENT);
        assert_se(access(y, F_OK) < 0 && errno == ENOENT);

        ASSERT_OK(mkdir(a, 0700));
        ASSERT_OK(mkdir(b, 0700));
        ASSERT_OK(mkdir(x, 0700));
        assert_se(mknod(y, S_IFREG | 0600, 0) >= 0);

        ASSERT_OK(chmod(b, 0000));
        ASSERT_OK(chmod(a, 0000));
        ASSERT_OK(chmod(y, 0000));
        ASSERT_OK(chmod(x, 0000));
        ASSERT_OK(chmod(d, 0500));

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_CHMOD_RESTORE|REMOVE_ONLY_DIRECTORIES) == -ENOTEMPTY);

        assert_se(access(a, F_OK) < 0 && errno == ENOENT);
        ASSERT_OK(access(d, F_OK));
        assert_se(stat(d, &st) >= 0 && (st.st_mode & 07777) == 0500);
        ASSERT_OK(access(x, F_OK));
        assert_se(stat(x, &st) >= 0 && (st.st_mode & 07777) == 0000);
        ASSERT_OK(chmod(x, 0700));
        ASSERT_OK(access(y, F_OK));
        assert_se(stat(y, &st) >= 0 && (st.st_mode & 07777) == 0000);

        ASSERT_OK(chmod(y, 0000));
        ASSERT_OK(chmod(x, 0000));
        ASSERT_OK(chmod(d, 0000));

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_CHMOD_RESTORE) >= 0);

        assert_se(stat(d, &st) >= 0 && (st.st_mode & 07777) == 0000);
        ASSERT_OK(access(d, F_OK));
        ASSERT_OK(chmod(d, 0700));
        assert_se(access(x, F_OK) < 0 && errno == ENOENT);

        ASSERT_OK(mkdir(x, 0700));
        assert_se(mknod(y, S_IFREG | 0600, 0) >= 0);

        ASSERT_OK(chmod(y, 0000));
        ASSERT_OK(chmod(x, 0000));
        ASSERT_OK(chmod(d, 0000));

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_ROOT) >= 0);

        assert_se(access(d, F_OK) < 0 && errno == ENOENT);
}

TEST(rm_rf_chmod) {
        int r;

        if (getuid() == 0) {
                /* This test only works unpriv (as only then the access mask for the owning user matters),
                 * hence drop privs here */

                r = safe_fork("(setresuid)", FORK_DEATHSIG_SIGTERM|FORK_WAIT, NULL);
                ASSERT_OK(r);

                if (r == 0) {
                        /* child */

                        ASSERT_OK(setresuid(1, 1, 1));

                        test_rm_rf_chmod_inner();
                        _exit(EXIT_SUCCESS);
                }

                return;
        }

        test_rm_rf_chmod_inner();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
