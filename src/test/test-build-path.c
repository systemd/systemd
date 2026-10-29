/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build-path.h"
#include "fs-util.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(get_build_exec_dir) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = get_build_exec_dir(&p);
        if (r == -ENOEXEC)
                log_info("Not run from build dir.");
        else if (r < 0)
                log_error_errno(r, "Failed to find build dir: %m");
        else
                log_info("%s", strna(p));
}

TEST(invoke_callout_binary_noexec) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        /* An empty executable file must make invoke_callout_binary() fail with ENOEXEC, and must not be
         * run as an empty shell script, which would exit successfully. */

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_NOT_NULL(p = path_join(d, "test-build-path-empty-callout"));
        ASSERT_OK(touch(p));
        ASSERT_OK_ERRNO(chmod(p, 0755));
        if (access(p, X_OK) < 0) /* e.g. /tmp/ mounted noexec */
                return (void) log_tests_skipped_errno(errno, "Cannot execute files in %s", d);

        r = ASSERT_OK(pidref_safe_fork("(invoke-callout)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pidref));
        if (r == 0) {
                r = invoke_callout_binary(p, STRV_MAKE(p));
                _exit(r == -ENOEXEC ? 77 : EXIT_FAILURE);
        }

        ASSERT_OK_EQ(pidref_wait_for_terminate_and_check("(invoke-callout)", &pidref, WAIT_LOG), 77);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
