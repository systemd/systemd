/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>

#include "bus-util.h"
#include "manager.h"
#include "manager-dump.h"
#include "rm-rf.h"
#include "service.h"
#include "slice.h"
#include "special.h"
#include "strv.h"
#include "tests.h"
#include "unit-serialize.h"

static void verify_dependency_atoms(void) {
        UnitDependencyAtom combined = 0, multi_use_atoms = 0;

        /* Let's guarantee that our dependency type/atom translation tables are fully correct */

        for (UnitDependency d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
                UnitDependencyAtom a;
                UnitDependency reverse;
                bool has_superset = false;

                assert_se((a = unit_dependency_to_atom(d)) >= 0);

                for (UnitDependency t = 0; t < _UNIT_DEPENDENCY_MAX; t++) {
                        UnitDependencyAtom b;

                        if (t == d)
                                continue;

                        assert_se((b = unit_dependency_to_atom(t)) >= 0);

                        if ((a & b) == a) {
                                has_superset = true;
                                break;
                        }
                }

                reverse = unit_dependency_from_unique_atom(a);
                assert_se(reverse == _UNIT_DEPENDENCY_INVALID || reverse >= 0);

                assert_se((reverse < 0) == has_superset); /* If one dependency type is a superset of another,
                                                           * then the reverse mapping is not unique, verify
                                                           * that. */

                log_info("Verified dependency type: %s", unit_dependency_to_string(d));

                multi_use_atoms |= combined & a;
                combined |= a;
        }

        /* Make sure all atoms are used, i.e. there's at least one dependency type that references it. */
        assert_se(combined == _UNIT_DEPENDENCY_ATOM_MAX);

        for (UnitDependencyAtom a = 1; a <= _UNIT_DEPENDENCY_ATOM_MAX; a <<= 1) {

                if (multi_use_atoms & a) {
                        /* If an atom is used by multiple dep types, then mapping the atom to a dependency is
                         * not unique and *must* fail */
                        assert_se(unit_dependency_from_unique_atom(a) == _UNIT_DEPENDENCY_INVALID);
                        continue;
                }

                /* If only a single dep type uses specific atom, let's guarantee our mapping table is
                complete, and thus the atom can be mapped to the single dep type that is used. */
                assert_se(unit_dependency_from_unique_atom(a) >= 0);
        }
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *g = NULL,
                *h = NULL, *i = NULL, *a_conj = NULL, *unit_with_multiple_dashes = NULL, *stub = NULL,
                *tomato = NULL, *sauce = NULL, *fruit = NULL, *zupa = NULL;
        Job *j;
        int r;

        test_setup_logging(LOG_DEBUG);

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

        printf("Load1:\n");
        assert_se(manager_load_startable_unit_or_warn(m, "a.service", NULL, &a) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "b.service", NULL, &b) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "c.service", NULL, &c) >= 0);
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test1: (Trivial)\n");
        r = manager_add_job(m, JOB_START, c, JOB_REPLACE, &err, &j);
        if (sd_bus_error_is_set(&err))
                log_error("error: %s: %s", err.name, err.message);
        assert_se(r == 0);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load2:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_startable_unit_or_warn(m, "d.service", NULL, &d) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "e.service", NULL, &e) >= 0);
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test2: (Cyclic Order, Unfixable)\n");
        assert_se(manager_add_job(m, JOB_START, d, JOB_REPLACE, NULL, &j) == -EDEADLK);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test3: (Cyclic Order, Fixable, Garbage Collector)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_REPLACE, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test4: (Identical transaction)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_FAIL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load3:\n");
        assert_se(manager_load_startable_unit_or_warn(m, "g.service", NULL, &g) >= 0);
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test5: (Colliding transaction, fail)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_FAIL, NULL, &j) == -EDEADLK);

        printf("Test6: (Colliding transaction, replace)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_REPLACE, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test7: (Unmergeable job type, fail)\n");
        assert_se(manager_add_job(m, JOB_STOP, g, JOB_FAIL, NULL, &j) == -EDEADLK);

        printf("Test8: (Mergeable job type, fail)\n");
        assert_se(manager_add_job(m, JOB_RESTART, g, JOB_FAIL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test9: (Unmergeable job type, replace)\n");
        assert_se(manager_add_job(m, JOB_STOP, g, JOB_REPLACE, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load4:\n");
        assert_se(manager_load_startable_unit_or_warn(m, "h.service", NULL, &h) >= 0);
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test10: (Unmergeable job type of auxiliary job, fail)\n");
        assert_se(manager_add_job(m, JOB_START, h, JOB_FAIL, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load5:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_startable_unit_or_warn(m, "i.service", NULL, &i) >= 0);
        SERVICE(a)->state = SERVICE_RUNNING;
        SERVICE(d)->state = SERVICE_RUNNING;
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test11: (Start/stop job ordering, execution cycle)\n");
        assert_se(manager_add_job(m, JOB_START, i, JOB_FAIL, NULL, &j) == 0);
        assert_se(unit_has_job_type(a, JOB_STOP));
        assert_se(unit_has_job_type(d, JOB_STOP));
        assert_se(unit_has_job_type(b, JOB_START));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load6:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_startable_unit_or_warn(m, "a-conj.service", NULL, &a_conj) >= 0);
        SERVICE(a)->state = SERVICE_DEAD;
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test12: (Trivial cycle, Unfixable)\n");
        assert_se(manager_add_job(m, JOB_START, a_conj, JOB_REPLACE, NULL, &j) == -EDEADLK);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        assert_se(!hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        assert_se(!hashmap_get(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        assert_se(!hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        assert_se(!hashmap_get(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        assert_se(unit_add_dependency(a, UNIT_PROPAGATES_RELOAD_TO, b, true, UNIT_DEPENDENCY_UDEV) >= 0);
        assert_se(unit_add_dependency(a, UNIT_PROPAGATES_RELOAD_TO, c, true, UNIT_DEPENDENCY_PROC_SWAP) >= 0);

        assert_se( hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        assert_se( hashmap_get(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        assert_se( hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        assert_se( hashmap_get(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        unit_remove_dependencies(a, UNIT_DEPENDENCY_UDEV);

        assert_se(!hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        assert_se(!hashmap_get(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        assert_se( hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        assert_se( hashmap_get(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        unit_remove_dependencies(a, UNIT_DEPENDENCY_PROC_SWAP);

        assert_se(!hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        assert_se(!hashmap_get(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        assert_se(!hashmap_get(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        assert_se(!hashmap_get(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        assert_se(manager_load_unit(m, "unit-with-multiple-dashes.service", NULL, NULL, &unit_with_multiple_dashes) >= 0);

        assert_se(strv_equal(unit_with_multiple_dashes->documentation, STRV_MAKE("man:test", "man:override2", "man:override3")));
        ASSERT_STREQ(unit_with_multiple_dashes->description, "override4");

        /* Now merge a synthetic unit into the existing one */
        assert_se(unit_new_for_name(m, sizeof(Service), "merged.service", &stub) >= 0);
        assert_se(unit_add_dependency_by_name(stub, UNIT_AFTER, SPECIAL_BASIC_TARGET, true, UNIT_DEPENDENCY_FILE) >= 0);
        assert_se(unit_add_dependency_by_name(stub, UNIT_AFTER, "quux.target", true, UNIT_DEPENDENCY_FILE) >= 0);
        assert_se(unit_add_dependency_by_name(stub, UNIT_AFTER, SPECIAL_ROOT_SLICE, true, UNIT_DEPENDENCY_FILE) >= 0);
        assert_se(unit_add_dependency_by_name(stub, UNIT_REQUIRES, "non-existing.mount", true, UNIT_DEPENDENCY_FILE) >= 0);
        assert_se(unit_add_dependency_by_name(stub, UNIT_ON_FAILURE, "non-existing-on-failure.target", true, UNIT_DEPENDENCY_FILE) >= 0);
        assert_se(unit_add_dependency_by_name(stub, UNIT_ON_SUCCESS, "non-existing-on-success.target", true, UNIT_DEPENDENCY_FILE) >= 0);

        log_info("/* Merging a+stub, dumps before */");
        unit_dump(a, stderr, NULL);
        unit_dump(stub, stderr, NULL);
        assert_se(unit_merge(a, stub) >= 0);
        log_info("/* Dump of merged a+stub */");
        unit_dump(a, stderr, NULL);

        assert_se( unit_has_dependency(a, UNIT_ATOM_AFTER, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        assert_se( unit_has_dependency(a, UNIT_ATOM_AFTER, manager_get_unit(m, "quux.target")));
        assert_se( unit_has_dependency(a, UNIT_ATOM_AFTER, manager_get_unit(m, SPECIAL_ROOT_SLICE)));
        assert_se( unit_has_dependency(a, UNIT_ATOM_PULL_IN_START, manager_get_unit(m, "non-existing.mount")));
        assert_se( unit_has_dependency(a, UNIT_ATOM_RETROACTIVE_START_REPLACE, manager_get_unit(m, "non-existing.mount")));
        assert_se( unit_has_dependency(a, UNIT_ATOM_ON_FAILURE, manager_get_unit(m, "non-existing-on-failure.target")));
        assert_se( unit_has_dependency(manager_get_unit(m, "non-existing-on-failure.target"), UNIT_ATOM_ON_FAILURE_OF, a));
        assert_se( unit_has_dependency(a, UNIT_ATOM_ON_SUCCESS, manager_get_unit(m, "non-existing-on-success.target")));
        assert_se( unit_has_dependency(manager_get_unit(m, "non-existing-on-success.target"), UNIT_ATOM_ON_SUCCESS_OF, a));
        assert_se(!unit_has_dependency(a, UNIT_ATOM_ON_FAILURE, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        assert_se(!unit_has_dependency(a, UNIT_ATOM_ON_SUCCESS, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        assert_se(!unit_has_dependency(a, UNIT_ATOM_ON_FAILURE_OF, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        assert_se(!unit_has_dependency(a, UNIT_ATOM_ON_SUCCESS_OF, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        assert_se(!unit_has_dependency(a, UNIT_ATOM_PROPAGATES_RELOAD_TO, manager_get_unit(m, "non-existing-on-failure.target")));

        assert_se(unit_has_name(a, "a.service"));
        assert_se(unit_has_name(a, "merged.service"));

        unsigned mm = 1;
        Unit *other;

        UNIT_FOREACH_DEPENDENCY(other, a, UNIT_ATOM_AFTER) {
                mm *= unit_has_name(other, SPECIAL_BASIC_TARGET) ? 3 : 1;
                mm *= unit_has_name(other, "quux.target") ? 5 : 1;
                mm *= unit_has_name(other, SPECIAL_ROOT_SLICE) ? 7 : 1;
        }

        UNIT_FOREACH_DEPENDENCY(other, a, UNIT_ATOM_ON_FAILURE)
                mm *= unit_has_name(other, "non-existing-on-failure.target") ? 11 : 1;

        UNIT_FOREACH_DEPENDENCY(other, a, UNIT_ATOM_PULL_IN_START)
                mm *= unit_has_name(other, "non-existing.mount") ? 13 : 1;

        assert_se(mm == 3U*5U*7U*11U*13U);

        verify_dependency_atoms();

        /* Test adding multiple Slice= dependencies; only the last should remain */
        assert_se(unit_new_for_name(m, sizeof(Service), "tomato.service", &tomato) >= 0);
        assert_se(unit_new_for_name(m, sizeof(Slice), "sauce.slice", &sauce) >= 0);
        assert_se(unit_new_for_name(m, sizeof(Slice), "fruit.slice", &fruit) >= 0);
        assert_se(unit_new_for_name(m, sizeof(Slice), "zupa.slice", &zupa) >= 0);

        unit_set_slice(tomato, sauce);
        unit_set_slice(tomato, fruit);
        unit_set_slice(tomato, zupa);

        assert_se(UNIT_GET_SLICE(tomato) == zupa);
        assert_se(!unit_has_dependency(tomato, UNIT_ATOM_IN_SLICE, sauce));
        assert_se(!unit_has_dependency(tomato, UNIT_ATOM_IN_SLICE, fruit));
        assert_se( unit_has_dependency(tomato, UNIT_ATOM_IN_SLICE, zupa));

        assert_se(!unit_has_dependency(tomato, UNIT_ATOM_REFERENCES, sauce));
        assert_se(!unit_has_dependency(tomato, UNIT_ATOM_REFERENCES, fruit));
        assert_se( unit_has_dependency(tomato, UNIT_ATOM_REFERENCES, zupa));

        assert_se(!unit_has_dependency(sauce, UNIT_ATOM_SLICE_OF, tomato));
        assert_se(!unit_has_dependency(fruit, UNIT_ATOM_SLICE_OF, tomato));
        assert_se( unit_has_dependency(zupa, UNIT_ATOM_SLICE_OF, tomato));

        assert_se(!unit_has_dependency(sauce, UNIT_ATOM_REFERENCED_BY, tomato));
        assert_se(!unit_has_dependency(fruit, UNIT_ATOM_REFERENCED_BY, tomato));
        assert_se( unit_has_dependency(zupa, UNIT_ATOM_REFERENCED_BY, tomato));

        return 0;
}
