/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2012 Holger Hans Peter Freyther
***/

#include <sched.h>

#include "all-units.h"
#include "macro.h"
#include "manager.h"
#include "rm-rf.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *idle_ok, *idle_bad, *rr_ok, *rr_bad, *rr_sched;
        Service *ser;
        int r;

        test_setup_logging(LOG_INFO);

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        /* prepare the test */
        _cleanup_free_ char *unit_dir = NULL;
        ASSERT_OK(get_testdata_dir("units", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));
        assert_se(runtime_dir = setup_fake_runtime_dir());

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (manager_errno_skip_test(r))
                return log_tests_skipped_errno(r, "manager_new");
        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

        /* load idle ok */
        assert_se(manager_load_startable_unit_or_warn(m, "sched_idle_ok.service", NULL, &idle_ok) >= 0);
        ser = SERVICE(idle_ok);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_OTHER);
        assert_se(ser->exec_context.cpu_sched_priority == 0);

        /*
         * load idle bad. This should print a warning but we have no way to look at it.
         */
        assert_se(manager_load_startable_unit_or_warn(m, "sched_idle_bad.service", NULL, &idle_bad) >= 0);
        ser = SERVICE(idle_ok);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_OTHER);
        assert_se(ser->exec_context.cpu_sched_priority == 0);

        /*
         * load rr ok.
         * Test that the default priority is moving from 0 to 1.
         */
        assert_se(manager_load_startable_unit_or_warn(m, "sched_rr_ok.service", NULL, &rr_ok) >= 0);
        ser = SERVICE(rr_ok);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_RR);
        assert_se(ser->exec_context.cpu_sched_priority == 1);

        /*
         * load rr bad.
         * Test that the value of 0 and 100 is ignored.
         */
        assert_se(manager_load_startable_unit_or_warn(m, "sched_rr_bad.service", NULL, &rr_bad) >= 0);
        ser = SERVICE(rr_bad);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_RR);
        assert_se(ser->exec_context.cpu_sched_priority == 1);

        /*
         * load rr change.
         * Test that anything between 1 and 99 can be set.
         */
        assert_se(manager_load_startable_unit_or_warn(m, "sched_rr_change.service", NULL, &rr_sched) >= 0);
        ser = SERVICE(rr_sched);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_RR);
        assert_se(ser->exec_context.cpu_sched_priority == 99);

        return EXIT_SUCCESS;
}
