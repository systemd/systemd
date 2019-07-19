/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bus-util.h"
#include "manager.h"
#include "rm-rf.h"
#include "strv.h"
#include "test-helper.h"
#include "tests.h"
#include "service.h"

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *g = NULL,
             *h = NULL, *i = NULL, *a_conj = NULL, *unit_with_multiple_dashes = NULL;
        Job *j;
        int r;

        test_setup_logging(LOG_DEBUG);

        r = enter_cgroup_subroot();
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        /* prepare the test */
        assert_se(set_unit_path(get_testdata_dir()) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());
        r = manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (MANAGER_SKIP_TEST(r))
                return log_tests_skipped_errno(r, "manager_new");
        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        printf("Load1:\n");
        assert_se(manager_load_startable_unit_or_warn(m, "a.service", NULL, &a) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "b.service", NULL, &b) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "c.service", NULL, &c) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test1: (Trivial)\n");
        r = manager_add_job(m, JOB_START, c, JOB_REPLACE, NULL, &err, &j);
        if (sd_bus_error_is_set(&err))
                log_error("error: %s: %s", err.name, err.message);
        assert_se(r == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load2:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_startable_unit_or_warn(m, "d.service", NULL, &d) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "e.service", NULL, &e) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test2: (Cyclic Order, Unfixable)\n");
        assert_se(manager_add_job(m, JOB_START, d, JOB_REPLACE, NULL, NULL, &j) == -EDEADLK);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test3: (Cyclic Order, Fixable, Garbage Collector)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_REPLACE, NULL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test4: (Identical transaction)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_FAIL, NULL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load3:\n");
        assert_se(manager_load_startable_unit_or_warn(m, "g.service", NULL, &g) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test5: (Colliding transaction, fail)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_FAIL, NULL, NULL, &j) == -EDEADLK);

        printf("Test6: (Colliding transaction, replace)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_REPLACE, NULL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test7: (Unmergeable job type, fail)\n");
        assert_se(manager_add_job(m, JOB_STOP, g, JOB_FAIL, NULL, NULL, &j) == -EDEADLK);

        printf("Test8: (Mergeable job type, fail)\n");
        assert_se(manager_add_job(m, JOB_RESTART, g, JOB_FAIL, NULL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test9: (Unmergeable job type, replace)\n");
        assert_se(manager_add_job(m, JOB_STOP, g, JOB_REPLACE, NULL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load4:\n");
        assert_se(manager_load_startable_unit_or_warn(m, "h.service", NULL, &h) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test10: (Unmergeable job type of auxiliary job, fail)\n");
        assert_se(manager_add_job(m, JOB_START, h, JOB_FAIL, NULL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load5:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_startable_unit_or_warn(m, "i.service", NULL, &i) >= 0);
        SERVICE(a)->state = SERVICE_RUNNING;
        SERVICE(d)->state = SERVICE_RUNNING;
        manager_dump_units(m, stdout, "\t");

        printf("Test11: (Start/stop job ordering, execution cycle)\n");
        assert_se(manager_add_job(m, JOB_START, i, JOB_FAIL, NULL, NULL, &j) == 0);
        assert_se(a->job && a->job->type == JOB_STOP);
        assert_se(d->job && d->job->type == JOB_STOP);
        assert_se(b->job && b->job->type == JOB_START);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load6:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_startable_unit_or_warn(m, "a-conj.service", NULL, &a_conj) >= 0);
        SERVICE(a)->state = SERVICE_DEAD;
        manager_dump_units(m, stdout, "\t");

        printf("Test12: (Trivial cycle, Unfixable)\n");
        assert_se(manager_add_job(m, JOB_START, a_conj, JOB_REPLACE, NULL, NULL, &j) == -EDEADLK);
        manager_dump_jobs(m, stdout, "\t");

        assert_se(!hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], b));
        assert_se(!hashmap_get(b->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));
        assert_se(!hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], c));
        assert_se(!hashmap_get(c->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));

        assert_se(unit_add_dependency(a, UNIT_PROPAGATES_RELOAD_TO, b, true, UNIT_DEPENDENCY_UDEV) == 0);
        assert_se(unit_add_dependency(a, UNIT_PROPAGATES_RELOAD_TO, c, true, UNIT_DEPENDENCY_PROC_SWAP) == 0);

        assert_se(hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], b));
        assert_se(hashmap_get(b->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));
        assert_se(hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], c));
        assert_se(hashmap_get(c->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));

        unit_remove_dependencies(a, UNIT_DEPENDENCY_UDEV);

        assert_se(!hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], b));
        assert_se(!hashmap_get(b->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));
        assert_se(hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], c));
        assert_se(hashmap_get(c->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));

        unit_remove_dependencies(a, UNIT_DEPENDENCY_PROC_SWAP);

        assert_se(!hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], b));
        assert_se(!hashmap_get(b->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));
        assert_se(!hashmap_get(a->dependencies[UNIT_PROPAGATES_RELOAD_TO], c));
        assert_se(!hashmap_get(c->dependencies[UNIT_RELOAD_PROPAGATED_FROM], a));

        assert_se(manager_load_unit(m, "unit-with-multiple-dashes.service", NULL, NULL, &unit_with_multiple_dashes) >= 0);

        assert_se(strv_equal(unit_with_multiple_dashes->documentation, STRV_MAKE("man:test", "man:override2", "man:override3")));
        assert_se(streq_ptr(unit_with_multiple_dashes->description, "override4"));

        return 0;
}
