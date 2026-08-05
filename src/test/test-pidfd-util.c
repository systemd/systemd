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

DEFINE_TEST_MAIN(LOG_DEBUG);
