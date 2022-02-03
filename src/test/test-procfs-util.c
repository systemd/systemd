/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "errno-util.h"
#include "format-util.h"
#include "log.h"
#include "procfs-util.h"
#include "process-util.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        nsec_t nsec;
        uint64_t v, pid_max, threads_max, limit;
        int r;

        log_parse_environment();
        log_open();

        assert_se(procfs_cpu_get_usage(&nsec) >= 0);
        log_info("Current system CPU time: %s", FORMAT_TIMESPAN(nsec/NSEC_PER_USEC, 1));

        assert_se(procfs_memory_get_used(&v) >= 0);
        log_info("Current memory usage: %s", FORMAT_BYTES(v));

        assert_se(procfs_tasks_get_current(&v) >= 0);
        log_info("Current number of tasks: %" PRIu64, v);

        pid_max = TASKS_MAX;
        r = procfs_get_pid_max(&pid_max);
        if (r == -ENOENT || ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped_errno(r, "can't get pid max");
        assert(r >= 0);
        log_info("kernel.pid_max: %"PRIu64, pid_max);

        threads_max = TASKS_MAX;
        r = procfs_get_threads_max(&threads_max);
        if (r == -ENOENT || ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped_errno(r, "can't get threads max");
        assert(r >= 0);
        log_info("kernel.threads-max: %"PRIu64, threads_max);

        limit = MIN(pid_max - (pid_max > 0), threads_max);

        assert_se(r >= 0);
        log_info("Limit of tasks: %" PRIu64, limit);
        assert_se(limit > 0);

        /* This call should never fail, as we're trying to set it to the same limit */
        assert(procfs_tasks_set_limit(limit) >= 0);

        if (limit > 100) {
                log_info("Reducing limit by one to %"PRIu64"…", limit-1);

                r = procfs_tasks_set_limit(limit-1);
                if (IN_SET(r, -ENOENT, -EROFS) || ERRNO_IS_PRIVILEGE(r))
                        return log_tests_skipped_errno(r, "can't set tasks limit");
                assert_se(r >= 0);

                assert_se(procfs_get_pid_max(&v) >= 0);
                /* We never decrease the pid_max, so it shouldn't have changed */
                assert_se(v == pid_max);

                assert_se(procfs_get_threads_max(&v) >= 0);
                assert_se(v == limit-1);

                assert_se(procfs_tasks_set_limit(limit) >= 0);

                assert_se(procfs_get_pid_max(&v) >= 0);
                assert_se(v == pid_max);

                assert_se(procfs_get_threads_max(&v) >= 0);
                assert_se(v == limit);
        }

        return 0;
}
