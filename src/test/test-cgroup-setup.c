/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "errno-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "tests.h"

static void test_is_wanted_print_one(bool header) {
        _cleanup_free_ char *cmdline = NULL;

        log_info("-- %s --", __func__);
        ASSERT_OK(proc_cmdline(&cmdline));
        log_info("cmdline: %s", cmdline);
        if (header)
                (void) system("findmnt -n /sys/fs/cgroup");

        log_info("is_unified_wanted() → %s", yes_no(cg_is_unified_wanted()));
        log_info("is_hybrid_wanted() → %s", yes_no(cg_is_hybrid_wanted()));
        log_info("is_legacy_wanted() → %s", yes_no(cg_is_legacy_wanted()));
        log_info(" ");
}

TEST(is_wanted_print) {
        test_is_wanted_print_one(true);
        test_is_wanted_print_one(false); /* run twice to test caching */
}

TEST(is_wanted) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_PROC_CMDLINE",
                               "systemd.unified_cgroup_hierarchy", 1));
        test_is_wanted_print_one(false);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_PROC_CMDLINE",
                               "systemd.unified_cgroup_hierarchy=0", 1));
        test_is_wanted_print_one(false);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_PROC_CMDLINE",
                               "systemd.unified_cgroup_hierarchy=0 "
                               "systemd.legacy_systemd_cgroup_controller", 1));
        test_is_wanted_print_one(false);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_PROC_CMDLINE",
                               "systemd.unified_cgroup_hierarchy=0 "
                               "systemd.legacy_systemd_cgroup_controller=0", 1));
        test_is_wanted_print_one(false);

        /* cgroup_no_v1=all implies unified cgroup hierarchy, unless otherwise
         * explicitly specified. */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_PROC_CMDLINE",
                               "cgroup_no_v1=all", 1));
        test_is_wanted_print_one(false);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_PROC_CMDLINE",
                               "cgroup_no_v1=all "
                               "systemd.unified_cgroup_hierarchy=0", 1));
        test_is_wanted_print_one(false);
}

static int intro(void) {
        if (access("/proc/cmdline", R_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return log_tests_skipped("can't read /proc/cmdline");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
