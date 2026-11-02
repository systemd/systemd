/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "errno-util.h"
#include "format-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "tests.h"

TEST(pidfd_get_inode_id_self_cached) {
        int r;

        log_info("pid=" PID_FMT, getpid_cached());

        uint64_t id;
        r = pidfd_get_inode_id_self_cached(&id);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                log_info("pidfdid not supported");
        else {
                assert(r >= 0);
                log_info("pidfdid=%" PRIu64, id);
        }
}

static int check_pidfd_id_differs(uint64_t parent_id) {
        uint64_t id;

        if (pidfd_get_inode_id_self_cached(&id) < 0)
                return EXIT_FAILURE;
        if (id == parent_id) {
                log_error("Cached pidfd ID %" PRIu64 " was inherited from parent.", id);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

TEST(pidfd_get_inode_id_self_cached_pidns) {
        uint64_t id;
        siginfo_t si;
        pid_t pid;
        int r;

        r = pidfd_get_inode_id_self_cached(&id);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped("pidfdid not supported");
        ASSERT_OK(r);

        /* Check that the cached pidfd ID is flushed in a forked child, both via fork() (i.e. via the
         * pthread_atfork() handler) and via raw_clone(), and also in the PID 1 → PID 1 case, where the
         * cache key (the PID) does not change. */

        ASSERT_OK_ERRNO(pid = fork());
        if (pid == 0) {
                if (check_pidfd_id_differs(id) != EXIT_SUCCESS)
                        _exit(EXIT_FAILURE);

                if (unshare(CLONE_NEWUSER|CLONE_NEWPID) < 0) {
                        log_notice_errno(errno, "Failed to unshare user and PID namespace, skipping PID 1 check: %m");
                        _exit(EXIT_SUCCESS);
                }

                /* First child in the new PID namespace, i.e. PID 1 */
                pid_t inner = fork();
                if (inner < 0)
                        _exit(EXIT_FAILURE);
                if (inner == 0) {
                        uint64_t pid1_id;

                        if (getpid_cached() != 1 || pidfd_get_inode_id_self_cached(&pid1_id) < 0)
                                _exit(EXIT_FAILURE);

                        /* Another PID 1, in a nested PID namespace */
                        pid_t nested = raw_clone(SIGCHLD|CLONE_NEWPID);
                        if (nested < 0)
                                _exit(EXIT_FAILURE);
                        if (nested == 0) {
                                if (getpid_cached() != 1)
                                        _exit(EXIT_FAILURE);
                                _exit(check_pidfd_id_differs(pid1_id));
                        }

                        siginfo_t nested_si;
                        if (waitid(P_PID, nested, &nested_si, WEXITED) < 0)
                                _exit(EXIT_FAILURE);
                        _exit(nested_si.si_code == CLD_EXITED ? nested_si.si_status : EXIT_FAILURE);
                }

                siginfo_t inner_si;
                if (waitid(P_PID, inner, &inner_si, WEXITED) < 0)
                        _exit(EXIT_FAILURE);
                _exit(inner_si.si_code == CLD_EXITED ? inner_si.si_status : EXIT_FAILURE);
        }

        ASSERT_OK_ERRNO(waitid(P_PID, pid, &si, WEXITED));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
}

TEST(pidfd_info_mask_is_supported) {
        int r;

        r = pidfd_info_mask_is_supported(PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_CGROUPID);
        if (r > 0)
                log_info("PIDFD_INFO_PID, PIDFD_INFO_CREDS, and PIDFD_INFO_CGROUPID are supported.");
        else {
                ASSERT_ERROR(r, EOPNOTSUPP);
                log_info("ioctl(PIDFD_GET_INFO) is not supported. Maybe the kernel is older than v6.13.");
        }

        /* The flag PIDFD_INFO_EXIT itself is supported since v6.15, but we have no way to check if it is
         * supported without PIDFD_INFO_SUPPORTED_MASK (since v6.19) (or, of course, we can check it by
         * terminating a process...). */
        if (ASSERT_OK_OR(pidfd_info_mask_is_supported(PIDFD_INFO_EXIT), -EOPNOTSUPP) > 0)
                log_info("PIDFD_INFO_EXIT is supported.");
        else
                log_info("PIDFD_INFO_EXIT is not supported. Maybe the kernel is older than v6.19.");

        /* Similar here. The flag PIDFD_INFO_COREDUMP itself is supported since v6.16. */
        if (ASSERT_OK_OR(pidfd_info_mask_is_supported(PIDFD_INFO_COREDUMP), -EOPNOTSUPP) > 0)
                log_info("PIDFD_INFO_COREDUMP is supported.");
        else
                log_info("PIDFD_INFO_COREDUMP is not supported. Maybe the kernel is older than v6.19.");

        if (ASSERT_OK_OR(pidfd_info_mask_is_supported(PIDFD_INFO_SUPPORTED_MASK), -EOPNOTSUPP) > 0)
                log_info("PIDFD_INFO_SUPPORTED_MASK is supported.");
        else
                log_info("PIDFD_INFO_SUPPORTED_MASK is not supported. Maybe the kernel is older than v6.19.");

        if (ASSERT_OK_OR(pidfd_info_mask_is_supported(PIDFD_INFO_COREDUMP_SIGNAL), -EOPNOTSUPP) > 0)
                log_info("PIDFD_INFO_COREDUMP_SIGNAL is supported.");
        else
                log_info("PIDFD_INFO_COREDUMP_SIGNAL is not supported. Maybe the kernel is older than v6.19.");

        if (ASSERT_OK_OR(pidfd_info_mask_is_supported(PIDFD_INFO_COREDUMP_CODE), -EOPNOTSUPP) > 0)
                log_info("PIDFD_INFO_COREDUMP_CODE is supported.");
        else
                log_info("PIDFD_INFO_COREDUMP_CODE is not supported. Maybe the kernel is older than v7.1.");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
