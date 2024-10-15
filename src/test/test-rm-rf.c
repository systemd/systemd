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

        assert_se(getuid() != 0);

        assert_se(mkdtemp_malloc("/tmp/test-rm-rf.XXXXXXX", &d) >= 0);
        a = strjoina(d, "/a");
        b = strjoina(a, "/b");
        x = strjoina(d, "/x");
        y = strjoina(x, "/y");

        assert_se(mkdir(x, 0700) >= 0);
        assert_se(mknod(y, S_IFREG | 0600, 0) >= 0);

        assert_se(chmod(y, 0400) >= 0);
        assert_se(chmod(x, 0500) >= 0);
        assert_se(chmod(d, 0500) >= 0);

        assert_se(rm_rf(d, REMOVE_PHYSICAL) == -EACCES);

        assert_se(access(d, F_OK) >= 0);
        assert_se(access(x, F_OK) >= 0);
        assert_se(access(y, F_OK) >= 0);

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD) >= 0);

        assert_se(access(d, F_OK) >= 0);
        assert_se(access(x, F_OK) < 0 && errno == ENOENT);
        assert_se(access(y, F_OK) < 0 && errno == ENOENT);

        assert_se(mkdir(a, 0700) >= 0);
        assert_se(mkdir(b, 0700) >= 0);
        assert_se(mkdir(x, 0700) >= 0);
        assert_se(mknod(y, S_IFREG | 0600, 0) >= 0);

        assert_se(chmod(b, 0000) >= 0);
        assert_se(chmod(a, 0000) >= 0);
        assert_se(chmod(y, 0000) >= 0);
        assert_se(chmod(x, 0000) >= 0);
        assert_se(chmod(d, 0500) >= 0);

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_CHMOD_RESTORE|REMOVE_ONLY_DIRECTORIES) == -ENOTEMPTY);

        assert_se(access(a, F_OK) < 0 && errno == ENOENT);
        assert_se(access(d, F_OK) >= 0);
        assert_se(stat(d, &st) >= 0 && (st.st_mode & 07777) == 0500);
        assert_se(access(x, F_OK) >= 0);
        assert_se(stat(x, &st) >= 0 && (st.st_mode & 07777) == 0000);
        assert_se(chmod(x, 0700) >= 0);
        assert_se(access(y, F_OK) >= 0);
        assert_se(stat(y, &st) >= 0 && (st.st_mode & 07777) == 0000);

        assert_se(chmod(y, 0000) >= 0);
        assert_se(chmod(x, 0000) >= 0);
        assert_se(chmod(d, 0000) >= 0);

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_CHMOD_RESTORE) >= 0);

        assert_se(stat(d, &st) >= 0 && (st.st_mode & 07777) == 0000);
        assert_se(access(d, F_OK) >= 0);
        assert_se(chmod(d, 0700) >= 0);
        assert_se(access(x, F_OK) < 0 && errno == ENOENT);

        assert_se(mkdir(x, 0700) >= 0);
        assert_se(mknod(y, S_IFREG | 0600, 0) >= 0);

        assert_se(chmod(y, 0000) >= 0);
        assert_se(chmod(x, 0000) >= 0);
        assert_se(chmod(d, 0000) >= 0);

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_CHMOD|REMOVE_ROOT) >= 0);

        assert_se(access(d, F_OK) < 0 && errno == ENOENT);
}

TEST(rm_rf_chmod) {
        int r;

        if (getuid() == 0 && userns_has_single_user())
                return (void) log_tests_skipped("running as root or in userns with single user");

        if (getuid() == 0) {
                /* This test only works unpriv (as only then the access mask for the owning user matters),
                 * hence drop privs here */

                r = safe_fork("(setresuid)", FORK_DEATHSIG_SIGTERM|FORK_WAIT, NULL);
                assert_se(r >= 0);

                if (r == 0) {
                        /* child */

                        assert_se(setresuid(1, 1, 1) >= 0);

                        test_rm_rf_chmod_inner();
                        _exit(EXIT_SUCCESS);
                }

                return;
        }

        test_rm_rf_chmod_inner();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
