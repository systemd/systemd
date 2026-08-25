/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "format-util.h"
#include "log.h"
#include "process-util.h"
#include "procfs-util.h"
#include "tests.h"
#include "time-util.h"

int main(int argc, char *argv[]) {
        nsec_t nsec;
        uint64_t v, pid_max, threads_max, limit;
        int r;

        test_setup_logging(LOG_DEBUG);

        ASSERT_OK(procfs_cpu_get_usage(&nsec));
        log_info("Current system CPU time: %s", FORMAT_TIMESPAN(nsec/NSEC_PER_USEC, 1));

        ProcfsCpuTicks ticks;
        ASSERT_OK(procfs_cpu_get_ticks(&ticks));
        log_info("Current CPU ticks: user=%" PRIu64 " nice=%" PRIu64 " system=%" PRIu64 " idle=%" PRIu64
                 " iowait=%" PRIu64 " irq=%" PRIu64 " softirq=%" PRIu64 " steal=%" PRIu64,
                 ticks.user, ticks.nice, ticks.system, ticks.idle,
                 ticks.iowait, ticks.irq, ticks.softirq, ticks.steal);
        ASSERT_GT(ticks.idle, 0U);

        ASSERT_OK(procfs_memory_get_used(&v));
        log_info("Current memory usage: %s", FORMAT_BYTES(v));

        ASSERT_OK(procfs_tasks_get_current(&v));
        log_info("Current number of tasks: %" PRIu64, v);

        pid_max = TASKS_MAX;
        r = procfs_get_pid_max(&pid_max);
        if (r == -ENOENT || ERRNO_IS_NEG_PRIVILEGE(r))
                return log_tests_skipped_errno(r, "can't get pid max");
        ASSERT_OK(r);
        log_info("kernel.pid_max: %"PRIu64, pid_max);

        threads_max = TASKS_MAX;
        r = procfs_get_threads_max(&threads_max);
        if (r == -ENOENT || ERRNO_IS_NEG_PRIVILEGE(r))
                return log_tests_skipped_errno(r, "can't get threads max");
        ASSERT_OK(r);
        log_info("kernel.threads-max: %"PRIu64, threads_max);

        limit = MIN(pid_max - (pid_max > 0), threads_max);
        log_info("Limit of tasks: %" PRIu64, limit);
        ASSERT_GT(limit, 0U);

        /* This call should never fail, as we're trying to set it to the same limit */
        ASSERT_OK(procfs_tasks_set_limit(limit));

        if (limit > 100) {
                log_info("Reducing limit by one to %"PRIu64"…", limit-1);

                r = procfs_tasks_set_limit(limit-1);
                if (r == -ENOENT || ERRNO_IS_NEG_FS_WRITE_REFUSED(r))
                        return log_tests_skipped_errno(r, "can't set tasks limit");
                ASSERT_OK(r);

                ASSERT_OK(procfs_get_pid_max(&v));
                /* We never decrease the pid_max, so it shouldn't have changed */
                ASSERT_EQ(v, pid_max);

                ASSERT_OK(procfs_get_threads_max(&v));
                ASSERT_EQ(v, limit - 1);

                ASSERT_OK(procfs_tasks_set_limit(limit));

                ASSERT_OK(procfs_get_pid_max(&v));
                ASSERT_EQ(v, pid_max);

                ASSERT_OK(procfs_get_threads_max(&v));
                ASSERT_EQ(v, limit);
        }

        return 0;
}
