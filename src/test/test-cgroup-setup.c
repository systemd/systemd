/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "cgroup-setup.h"
#include "errno-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "tests.h"

static void test_is_wanted_print(bool header) {
        _cleanup_free_ char *cmdline = NULL;

        log_info("-- %s --", __func__);
        assert_se(proc_cmdline(&cmdline) >= 0);
        log_info("cmdline: %s", cmdline);
        if (header) {
                log_info("default-hierarchy=" DEFAULT_HIERARCHY_NAME);
                (void) system("findmnt -n /sys/fs/cgroup");
        }

        log_info("is_unified_wanted() → %s", yes_no(cg_is_unified_wanted()));
        log_info("is_hybrid_wanted() → %s", yes_no(cg_is_hybrid_wanted()));
        log_info("is_legacy_wanted() → %s", yes_no(cg_is_legacy_wanted()));
        log_info(" ");
}

static void test_is_wanted(void) {
        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy=0", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy=0 "
                         "systemd.legacy_systemd_cgroup_controller", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy=0 "
                         "systemd.legacy_systemd_cgroup_controller=0", 1) >= 0);
        test_is_wanted_print(false);

        /* cgroup_no_v1=all implies unified cgroup hierarchy, unless otherwise
         * explicitly specified. */
        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "cgroup_no_v1=all", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "cgroup_no_v1=all "
                         "systemd.unified_cgroup_hierarchy=0", 1) >= 0);
        test_is_wanted_print(false);
}

int main(void) {
        test_setup_logging(LOG_DEBUG);

        if (access("/proc/cmdline", R_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return log_tests_skipped("can't read /proc/cmdline");

        test_is_wanted_print(true);
        test_is_wanted_print(false); /* run twice to test caching */
        test_is_wanted();

        return 0;
}
