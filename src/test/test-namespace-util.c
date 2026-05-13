/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "capability-util.h"
#include "errno-util.h"
#include "pidref.h"
#include "process-util.h"
#include "fd-util.h"
#include "namespace-util.h"
#include "tests.h"

TEST(namespace_enter) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        r = pidref_safe_fork(
                        "test-ns-enter-1",
                        FORK_NEW_USERNS|FORK_NEW_MOUNTNS|FORK_LOG|FORK_FREEZE|FORK_DEATHSIG_SIGKILL,
                        &pidref);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Unable to unshare user namespace");

        ASSERT_OK(r);

        _cleanup_close_ int mntns_fd = -EBADF, userns_fd = -EBADF, root_fd = -EBADF;
        ASSERT_OK(pidref_namespace_open(&pidref, NULL, &mntns_fd, NULL, &userns_fd, &root_fd));

        r = ASSERT_OK(pidref_safe_fork(
                        "test-ns-enter-2",
                        FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL,
                        NULL));
        if (r == 0) {
                ASSERT_OK(namespace_enter(-EBADF, mntns_fd, -EBADF, userns_fd, root_fd));
                _exit(EXIT_SUCCESS);
        }

        /* Make sure we can enter the namespaces as well if we don't have CAP_SYS_ADMIN. */
        r = ASSERT_OK(pidref_safe_fork(
                        "test-ns-enter-3",
                        FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL,
                        NULL));
        if (r == 0) {
                ASSERT_OK(drop_capability(CAP_SYS_ADMIN));
                ASSERT_OK(namespace_enter(-EBADF, mntns_fd, -EBADF, userns_fd, root_fd));
                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
