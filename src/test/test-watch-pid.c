/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "manager.h"
#include "process-util.h"
#include "rm-rf.h"
#include "service.h"
#include "set.h"
#include "tests.h"

TEST(watch_pid) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *a, *b, *c, *u;

        _cleanup_free_ char *unit_dir = NULL;
        ASSERT_OK(get_testdata_dir("units/", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));

        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());

        ASSERT_OK(manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m));
        ASSERT_OK(manager_startup(m, NULL, NULL, NULL));

        ASSERT_NOT_NULL(a = unit_new(m, sizeof(Service)));
        ASSERT_OK(unit_add_name(a, "a.service"));
        ASSERT_TRUE(set_isempty(a->pids));

        ASSERT_NOT_NULL(b = unit_new(m, sizeof(Service)));
        ASSERT_OK(unit_add_name(b, "b.service"));
        ASSERT_TRUE(set_isempty(b->pids));

        ASSERT_NOT_NULL(c = unit_new(m, sizeof(Service)));
        ASSERT_OK(unit_add_name(c, "c.service"));
        ASSERT_TRUE(set_isempty(c->pids));

        /* Fork off a child so that we have a PID to watch */
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        ASSERT_OK_POSITIVE(pidref_safe_fork("(child)", FORK_FREEZE, &pidref));

        ASSERT_TRUE(hashmap_isempty(m->watch_pids));
        ASSERT_NULL(manager_get_unit_by_pidref(m, &pidref));

        ASSERT_OK(unit_watch_pidref(a, &pidref, false));
        ASSERT_PTR_EQ(manager_get_unit_by_pidref(m, &pidref), a);

        ASSERT_OK(unit_watch_pidref(a, &pidref, false));
        ASSERT_PTR_EQ(manager_get_unit_by_pidref(m, &pidref), a);

        ASSERT_OK(unit_watch_pidref(b, &pidref, false));
        u = manager_get_unit_by_pidref(m, &pidref);
        ASSERT_TRUE(u == a || u == b);

        ASSERT_OK(unit_watch_pidref(b, &pidref, false));
        u = manager_get_unit_by_pidref(m, &pidref);
        ASSERT_TRUE(u == a || u == b);

        ASSERT_OK(unit_watch_pidref(c, &pidref, false));
        u = manager_get_unit_by_pidref(m, &pidref);
        ASSERT_TRUE(u == a || u == b || u == c);

        ASSERT_OK(unit_watch_pidref(c, &pidref, false));
        u = manager_get_unit_by_pidref(m, &pidref);
        ASSERT_TRUE(u == a || u == b || u == c);

        unit_unwatch_pidref(b, &pidref);
        u = manager_get_unit_by_pidref(m, &pidref);
        ASSERT_TRUE(u == a || u == c);

        unit_unwatch_pidref(b, &pidref);
        u = manager_get_unit_by_pidref(m, &pidref);
        ASSERT_TRUE(u == a || u == c);

        unit_unwatch_pidref(a, &pidref);
        ASSERT_PTR_EQ(manager_get_unit_by_pidref(m, &pidref), c);

        unit_unwatch_pidref(a, &pidref);
        ASSERT_PTR_EQ(manager_get_unit_by_pidref(m, &pidref), c);

        unit_unwatch_pidref(c, &pidref);
        ASSERT_NULL(manager_get_unit_by_pidref(m, &pidref));

        unit_unwatch_pidref(c, &pidref);
        ASSERT_NULL(manager_get_unit_by_pidref(m, &pidref));
}

static int intro(void) {
        int r;

        if (getuid() != 0)
                return log_tests_skipped("not root");

        r = enter_cgroup_subroot(NULL);
        if (r < 0)
                return log_tests_skipped_errno(r, "cgroupfs not available");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
