/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_rm_rf_chmod_inner(void) {
        _cleanup_free_ char *d = NULL;
        const char *x, *y;

        assert_se(getuid() != 0);

        assert_se(mkdtemp_malloc(NULL, &d) >= 0);

        x = strjoina(d, "/d");
        assert_se(mkdir(x, 0700) >= 0);
        y = strjoina(x, "/f");
        assert_se(mknod(y, S_IFREG | 0600, 0) >= 0);

        assert_se(chmod(y, 0400) >= 0);
        assert_se(chmod(x, 0500) >= 0);
        assert_se(chmod(d, 0500) >= 0);

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_ROOT) == -EACCES);

        assert_se(access(d, F_OK) >= 0);
        assert_se(access(x, F_OK) >= 0);
        assert_se(access(y, F_OK) >= 0);

        assert_se(rm_rf(d, REMOVE_PHYSICAL|REMOVE_ROOT|REMOVE_CHMOD) >= 0);

        errno = 0;
        assert_se(access(d, F_OK) < 0 && errno == ENOENT);
}

static void test_rm_rf_chmod(void) {
        int r;

        log_info("/* %s */", __func__);

        if (getuid() == 0) {
                /* This test only works unpriv (as only then the access mask for the owning user matters),
                 * hence drop privs here */

                r = safe_fork("(setresuid)", FORK_DEATHSIG|FORK_WAIT, NULL);
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

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_rm_rf_chmod();

        return 0;
}
