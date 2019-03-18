/* SPDX-License-Identifier: LGPL-2.1+ */

#include "log.h"
#include "manager.h"
#include "rm-rf.h"
#include "service.h"
#include "test-helper.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *a, *b, *c, *u;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                return log_tests_skipped("not root");
        r = enter_cgroup_subroot();
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(set_unit_path(get_testdata_dir()) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());

        assert_se(manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_BASIC, &m) >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        assert_se(a = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(a, "a.service") >= 0);
        assert_se(set_isempty(a->pids));

        assert_se(b = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(b, "b.service") >= 0);
        assert_se(set_isempty(b->pids));

        assert_se(c = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(c, "c.service") >= 0);
        assert_se(set_isempty(c->pids));

        assert_se(hashmap_isempty(m->watch_pids));
        assert_se(manager_get_unit_by_pid(m, 4711) == NULL);

        assert_se(unit_watch_pid(a, 4711, false) >= 0);
        assert_se(manager_get_unit_by_pid(m, 4711) == a);

        assert_se(unit_watch_pid(a, 4711, false) >= 0);
        assert_se(manager_get_unit_by_pid(m, 4711) == a);

        assert_se(unit_watch_pid(b, 4711, false) >= 0);
        u = manager_get_unit_by_pid(m, 4711);
        assert_se(u == a || u == b);

        assert_se(unit_watch_pid(b, 4711, false) >= 0);
        u = manager_get_unit_by_pid(m, 4711);
        assert_se(u == a || u == b);

        assert_se(unit_watch_pid(c, 4711, false) >= 0);
        u = manager_get_unit_by_pid(m, 4711);
        assert_se(u == a || u == b || u == c);

        assert_se(unit_watch_pid(c, 4711, false) >= 0);
        u = manager_get_unit_by_pid(m, 4711);
        assert_se(u == a || u == b || u == c);

        unit_unwatch_pid(b, 4711);
        u = manager_get_unit_by_pid(m, 4711);
        assert_se(u == a || u == c);

        unit_unwatch_pid(b, 4711);
        u = manager_get_unit_by_pid(m, 4711);
        assert_se(u == a || u == c);

        unit_unwatch_pid(a, 4711);
        assert_se(manager_get_unit_by_pid(m, 4711) == c);

        unit_unwatch_pid(a, 4711);
        assert_se(manager_get_unit_by_pid(m, 4711) == c);

        unit_unwatch_pid(c, 4711);
        assert_se(manager_get_unit_by_pid(m, 4711) == NULL);

        unit_unwatch_pid(c, 4711);
        assert_se(manager_get_unit_by_pid(m, 4711) == NULL);

        return 0;
}
