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
        uint64_t v, w;
        int r;

        log_parse_environment();
        log_open();

        assert_se(procfs_cpu_get_usage(&nsec) >= 0);
        log_info("Current system CPU time: %s", FORMAT_TIMESPAN(nsec/NSEC_PER_USEC, 1));

        assert_se(procfs_memory_get_used(&v) >= 0);
        log_info("Current memory usage: %s", FORMAT_BYTES(v));

        assert_se(procfs_tasks_get_current(&v) >= 0);
        log_info("Current number of tasks: %" PRIu64, v);

        v = TASKS_MAX;
        r = procfs_get_pid_max(&v);
        assert(r >= 0 || r == -ENOENT || ERRNO_IS_PRIVILEGE(r));
        log_info("kernel.pid_max: %"PRIu64, v);

        w = TASKS_MAX;
        r = procfs_get_threads_max(&w);
        assert(r >= 0 || r == -ENOENT || ERRNO_IS_PRIVILEGE(r));
        log_info("kernel.threads-max: %"PRIu64, w);

        v = MIN(v - (v > 0), w);

        assert_se(r >= 0);
        log_info("Limit of tasks: %" PRIu64, v);
        assert_se(v > 0);
        r = procfs_tasks_set_limit(v);
        if (r == -ENOENT || ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped("can't set task limits");
        assert(r >= 0);

        if (v > 100) {
                log_info("Reducing limit by one to %"PRIu64"…", v-1);

                r = procfs_tasks_set_limit(v-1);
                log_info_errno(r, "procfs_tasks_set_limit: %m");
                assert_se(r >= 0 || ERRNO_IS_PRIVILEGE(r));

                assert_se(procfs_get_threads_max(&w) >= 0);
                assert_se(r >= 0 ? w == v - 1 : w == v);

                assert_se(procfs_tasks_set_limit(v) >= 0);

                assert_se(procfs_get_threads_max(&w) >= 0);
                assert_se(v == w);
        }

        return 0;
}
