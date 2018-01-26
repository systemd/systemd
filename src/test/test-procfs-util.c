/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "log.h"
#include "procfs-util.h"

int main(int argc, char *argv[]) {
        uint64_t v;
        int r;

        log_parse_environment();
        log_open();

        assert_se(procfs_tasks_get_current(&v) >= 0);
        log_info("Current number of tasks: %" PRIu64, v);

        assert_se(procfs_tasks_get_limit(&v) >= 0);
        log_info("Limit of tasks: %" PRIu64, v);
        assert_se(v > 0);
        assert_se(procfs_tasks_set_limit(v) >= 0);

        if (v > 100) {
                uint64_t w;
                r = procfs_tasks_set_limit(v-1);
                assert_se(IN_SET(r, 0, -EPERM, -EACCES, -EROFS));

                assert_se(procfs_tasks_get_limit(&w) >= 0);
                assert_se((r == 0 && w == v - 1) || (r < 0 && w == v));

                assert_se(procfs_tasks_set_limit(v) >= 0);

                assert_se(procfs_tasks_get_limit(&w) >= 0);
                assert_se(v == w);
        }

        return 0;
}
