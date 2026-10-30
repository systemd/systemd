/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
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
#include "time-util.h"
#include "tmpfile-util.h"

#define EXIT_EXPECTED_ERROR 42

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

static void test_invoke_one(const char *name, const char *search_path, int expected_error) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        /* If expected_error is 0, the binary is expected to be executed and to exit successfully. Otherwise
         * invoke_callout_binary() is expected to return expected_error. */

        r = ASSERT_OK(pidref_safe_fork("(invoke-callout)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pidref));
        if (r == 0) {
                if (search_path && setenv("PATH", search_path, /* overwrite= */ true) < 0) {
                        log_error_errno(errno, "Failed to set $PATH: %m");
                        _exit(EXIT_FAILURE);
                }

                r = invoke_callout_binary(name, STRV_MAKE(name));
                if (r != expected_error) {
                        log_error_errno(r, "invoke_callout_binary(\"%s\") returned unexpected error: %m", name);
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_EXPECTED_ERROR);
        }

        int expected_exit_status = expected_error == 0 ? EXIT_SUCCESS : EXIT_EXPECTED_ERROR;
        ASSERT_OK_EQ(pidref_wait_for_terminate_and_check("(invoke-callout)", &pidref, WAIT_LOG_ABNORMAL),
                     expected_exit_status);
}

TEST(invoke_callout_binary_enoexec) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_free_ char *p = NULL;

        /* An empty executable file must make invoke_callout_binary() fail with ENOEXEC, and must not be
         * run as an empty shell script, which would exit successfully. */

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_NOT_NULL(p = path_join(d, "test-build-path-empty-callout"));
        ASSERT_OK(touch_file(p, /* parents= */ false, USEC_INFINITY, UID_INVALID, GID_INVALID, 0755));
        if (access(p, X_OK) < 0) /* e.g. /tmp/ mounted noexec */
                return (void) log_tests_skipped_errno(errno, "Cannot execute files in %s", d);

        test_invoke_one(p, /* search_path= */ NULL, -ENOEXEC);
        test_invoke_one("test-build-path-empty-callout", d, -ENOEXEC);
        test_invoke_one("test-build-path-missing-callout", d, -ENOENT);
        test_invoke_one("true", /* search_path= */ NULL, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
