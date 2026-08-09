/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "format-util.h"
#include "pidfd-util.h"
#include "process-util.h"
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
