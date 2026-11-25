/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-bus.h"

#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "manager.h"
#include "manager-dump.h"
#include "path-util.h"
#include "rm-rf.h"
#include "serialize.h"
#include "service.h"
#include "slice.h"
#include "special.h"
#include "strv.h"
#include "tests.h"
#include "unit-serialize.h"

static bool have_cgroup_subroot;

static void verify_dependency_atoms(void) {
        UnitDependencyAtom combined = 0, multi_use_atoms = 0;

        /* Let's guarantee that our dependency type/atom translation tables are fully correct */

        for (UnitDependency d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
                UnitDependencyAtom a;
                UnitDependency reverse;
                bool has_superset = false;

                a = ASSERT_OK(unit_dependency_to_atom(d));

                for (UnitDependency t = 0; t < _UNIT_DEPENDENCY_MAX; t++) {
                        UnitDependencyAtom b;

                        if (t == d)
                                continue;

                        b = ASSERT_OK(unit_dependency_to_atom(t));

                        if ((a & b) == a) {
                                has_superset = true;
                                break;
                        }
                }

                reverse = unit_dependency_from_unique_atom(a);
                ASSERT_TRUE(reverse == _UNIT_DEPENDENCY_INVALID || reverse >= 0);

                ASSERT_EQ(reverse < 0, has_superset); /* If one dependency type is a superset of another,
                                                      * then the reverse mapping is not unique, verify
                                                      * that. */

                log_info("Verified dependency type: %s", unit_dependency_to_string(d));

                multi_use_atoms |= combined & a;
                combined |= a;
        }

        /* Make sure all atoms are used, i.e. there's at least one dependency type that references it. */
        ASSERT_EQ(combined, _UNIT_DEPENDENCY_ATOM_MAX);

        for (UnitDependencyAtom a = 1; a <= _UNIT_DEPENDENCY_ATOM_MAX; a <<= 1) {

                if (multi_use_atoms & a) {
                        /* If an atom is used by multiple dep types, then mapping the atom to a dependency is
                         * not unique and *must* fail */
                        ASSERT_EQ(unit_dependency_from_unique_atom(a), _UNIT_DEPENDENCY_INVALID);
                        continue;
                }

                /* If only a single dep type uses specific atom, let's guarantee our mapping table is
                complete, and thus the atom can be mapped to the single dep type that is used. */
                ASSERT_OK(unit_dependency_from_unique_atom(a));
        }
}

TEST(engine) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *g = NULL,
                *h = NULL, *i = NULL, *a_conj = NULL, *unit_with_multiple_dashes = NULL, *stub = NULL,
                *tomato = NULL, *sauce = NULL, *fruit = NULL, *zupa = NULL;
        Job *j;
        int r;

        /* prepare the test */
        _cleanup_free_ char *unit_dir = NULL;
        ASSERT_OK(get_testdata_dir("test-engine", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));
        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (manager_errno_skip_test(r))
                return (void) log_tests_skipped_errno(r, "manager_new");
        ASSERT_OK(r);
        ASSERT_OK(manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, /* named_listen_fds= */ NULL, /* root= */ NULL));

        printf("Load1:\n");
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "a.service", /* path= */ NULL, LOG_ERR, &a));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "b.service", /* path= */ NULL, LOG_ERR, &b));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "c.service", /* path= */ NULL, LOG_ERR, &c));
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test1: (Trivial)\n");
        r = manager_add_job(m, JOB_START, c, JOB_REPLACE, &err, &j);
        if (sd_bus_error_is_set(&err))
                log_error("error: %s: %s", err.name, err.message);
        ASSERT_OK_ZERO(r);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load2:\n");
        manager_clear_jobs(m);
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "d.service", /* path= */ NULL, LOG_ERR, &d));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "e.service", /* path= */ NULL, LOG_ERR, &e));
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test2: (Cyclic Order, Unfixable)\n");
        ASSERT_ERROR(manager_add_job(m, JOB_START, d, JOB_REPLACE, /* reterr_error= */ NULL, &j), EDEADLK);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test3: (Cyclic Order, Fixable, Garbage Collector)\n");
        ASSERT_OK_ZERO(manager_add_job(m, JOB_START, e, JOB_REPLACE, /* reterr_error= */ NULL, &j));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test4: (Identical transaction)\n");
        ASSERT_OK_ZERO(manager_add_job(m, JOB_START, e, JOB_FAIL, /* reterr_error= */ NULL, &j));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load3:\n");
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "g.service", /* path= */ NULL, LOG_ERR, &g));
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test5: (Colliding transaction, fail)\n");
        ASSERT_ERROR(manager_add_job(m, JOB_START, g, JOB_FAIL, /* reterr_error= */ NULL, &j), EDEADLK);

        printf("Test6: (Colliding transaction, replace)\n");
        ASSERT_OK_ZERO(manager_add_job(m, JOB_START, g, JOB_REPLACE, /* reterr_error= */ NULL, &j));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test7: (Unmergeable job type, fail)\n");
        ASSERT_ERROR(manager_add_job(m, JOB_STOP, g, JOB_FAIL, /* reterr_error= */ NULL, &j), EDEADLK);

        printf("Test8: (Mergeable job type, fail)\n");
        ASSERT_OK_ZERO(manager_add_job(m, JOB_RESTART, g, JOB_FAIL, /* reterr_error= */ NULL, &j));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test9: (Unmergeable job type, replace)\n");
        ASSERT_OK_ZERO(manager_add_job(m, JOB_STOP, g, JOB_REPLACE, /* reterr_error= */ NULL, &j));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load4:\n");
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "h.service", /* path= */ NULL, LOG_ERR, &h));
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test10: (Unmergeable job type of auxiliary job, fail)\n");
        ASSERT_OK_ZERO(manager_add_job(m, JOB_START, h, JOB_FAIL, /* reterr_error= */ NULL, &j));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load5:\n");
        manager_clear_jobs(m);
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "i.service", /* path= */ NULL, LOG_ERR, &i));
        SERVICE(a)->state = SERVICE_RUNNING;
        SERVICE(d)->state = SERVICE_RUNNING;
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test11: (Start/stop job ordering, execution cycle)\n");
        ASSERT_OK_ZERO(manager_add_job(m, JOB_START, i, JOB_FAIL, /* reterr_error= */ NULL, &j));
        ASSERT_TRUE(unit_has_job_type(a, JOB_STOP));
        ASSERT_TRUE(unit_has_job_type(d, JOB_STOP));
        ASSERT_TRUE(unit_has_job_type(b, JOB_START));
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        printf("Load6:\n");
        manager_clear_jobs(m);
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "a-conj.service", /* path= */ NULL, LOG_ERR, &a_conj));
        SERVICE(a)->state = SERVICE_DEAD;
        manager_dump_units(m, stdout, /* patterns= */ NULL, "\t");

        printf("Test12: (Trivial cycle, Unfixable)\n");
        ASSERT_ERROR(manager_add_job(m, JOB_START, a_conj, JOB_REPLACE, /* reterr_error= */ NULL, &j), EDEADLK);
        manager_dump_jobs(m, stdout, /* patterns= */ NULL, "\t");

        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        ASSERT_OK(unit_add_dependency(a, UNIT_PROPAGATES_RELOAD_TO, b, /* add_reference= */ true, UNIT_DEPENDENCY_UDEV));
        ASSERT_OK(unit_add_dependency(a, UNIT_PROPAGATES_RELOAD_TO, c, /* add_reference= */ true, UNIT_DEPENDENCY_PROC_SWAP));

        ASSERT_TRUE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        ASSERT_TRUE(hashmap_contains(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        ASSERT_TRUE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        ASSERT_TRUE(hashmap_contains(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        unit_remove_dependencies(a, UNIT_DEPENDENCY_UDEV);

        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        ASSERT_TRUE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        ASSERT_TRUE(hashmap_contains(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        unit_remove_dependencies(a, UNIT_DEPENDENCY_PROC_SWAP);

        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), b));
        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(b, UNIT_RELOAD_PROPAGATED_FROM), a));
        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(a, UNIT_PROPAGATES_RELOAD_TO), c));
        ASSERT_FALSE(hashmap_contains(unit_get_dependencies(c, UNIT_RELOAD_PROPAGATED_FROM), a));

        ASSERT_OK(manager_load_unit(m, "unit-with-multiple-dashes.service", /* path= */ NULL, NULL, &unit_with_multiple_dashes));

        ASSERT_STRV_EQ_SET(unit_with_multiple_dashes->documentation, "man:test", "man:override2", "man:override3");
        ASSERT_STREQ(unit_with_multiple_dashes->description, "override4");

        /* Now merge a synthetic unit into the existing one */
        ASSERT_OK(unit_new_for_name(m, sizeof(Service), "merged.service", &stub));
        ASSERT_OK(unit_add_dependency_by_name(stub, UNIT_AFTER, SPECIAL_BASIC_TARGET, /* add_reference= */ true, UNIT_DEPENDENCY_FILE));
        ASSERT_OK(unit_add_dependency_by_name(stub, UNIT_AFTER, "quux.target", /* add_reference= */ true, UNIT_DEPENDENCY_FILE));
        ASSERT_OK(unit_add_dependency_by_name(stub, UNIT_AFTER, SPECIAL_ROOT_SLICE, /* add_reference= */ true, UNIT_DEPENDENCY_FILE));
        ASSERT_OK(unit_add_dependency_by_name(stub, UNIT_REQUIRES, "non-existing.mount", /* add_reference= */ true, UNIT_DEPENDENCY_FILE));
        ASSERT_OK(unit_add_dependency_by_name(stub, UNIT_ON_FAILURE, "non-existing-on-failure.target", /* add_reference= */ true, UNIT_DEPENDENCY_FILE));
        ASSERT_OK(unit_add_dependency_by_name(stub, UNIT_ON_SUCCESS, "non-existing-on-success.target", /* add_reference= */ true, UNIT_DEPENDENCY_FILE));

        log_info("/* Merging a+stub, dumps before */");
        unit_dump(a, stderr, /* prefix= */ NULL);
        unit_dump(stub, stderr, /* prefix= */ NULL);
        ASSERT_OK(unit_merge(a, stub));
        log_info("/* Dump of merged a+stub */");
        unit_dump(a, stderr, /* prefix= */ NULL);

        ASSERT_NOT_NULL(unit_has_dependency(a, UNIT_ATOM_AFTER, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        ASSERT_NOT_NULL(unit_has_dependency(a, UNIT_ATOM_AFTER, manager_get_unit(m, "quux.target")));
        ASSERT_NOT_NULL(unit_has_dependency(a, UNIT_ATOM_AFTER, manager_get_unit(m, SPECIAL_ROOT_SLICE)));
        ASSERT_NOT_NULL(unit_has_dependency(a, UNIT_ATOM_PULL_IN_START, manager_get_unit(m, "non-existing.mount")));
        ASSERT_NOT_NULL(unit_has_dependency(a, UNIT_ATOM_RETROACTIVE_START_REPLACE, manager_get_unit(m, "non-existing.mount")));
        ASSERT_NOT_NULL(unit_has_dependency(a, UNIT_ATOM_ON_FAILURE, manager_get_unit(m, "non-existing-on-failure.target")));
        ASSERT_NOT_NULL(unit_has_dependency(manager_get_unit(m, "non-existing-on-failure.target"), UNIT_ATOM_ON_FAILURE_OF, a));
        ASSERT_NOT_NULL(unit_has_dependency(a, UNIT_ATOM_ON_SUCCESS, manager_get_unit(m, "non-existing-on-success.target")));
        ASSERT_NOT_NULL(unit_has_dependency(manager_get_unit(m, "non-existing-on-success.target"), UNIT_ATOM_ON_SUCCESS_OF, a));
        ASSERT_NULL(unit_has_dependency(a, UNIT_ATOM_ON_FAILURE, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        ASSERT_NULL(unit_has_dependency(a, UNIT_ATOM_ON_SUCCESS, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        ASSERT_NULL(unit_has_dependency(a, UNIT_ATOM_ON_FAILURE_OF, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        ASSERT_NULL(unit_has_dependency(a, UNIT_ATOM_ON_SUCCESS_OF, manager_get_unit(m, SPECIAL_BASIC_TARGET)));
        ASSERT_NULL(unit_has_dependency(a, UNIT_ATOM_PROPAGATES_RELOAD_TO, manager_get_unit(m, "non-existing-on-failure.target")));

        ASSERT_TRUE(unit_has_name(a, "a.service"));
        ASSERT_TRUE(unit_has_name(a, "merged.service"));

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

        ASSERT_EQ(mm, 3U*5U*7U*11U*13U);

        verify_dependency_atoms();

        /* Test adding multiple Slice= dependencies; only the last should remain */
        ASSERT_OK(unit_new_for_name(m, sizeof(Service), "tomato.service", &tomato));
        ASSERT_OK(unit_new_for_name(m, sizeof(Slice), "sauce.slice", &sauce));
        ASSERT_OK(unit_new_for_name(m, sizeof(Slice), "fruit.slice", &fruit));
        ASSERT_OK(unit_new_for_name(m, sizeof(Slice), "zupa.slice", &zupa));

        unit_set_slice(tomato, sauce);
        unit_set_slice(tomato, fruit);
        unit_set_slice(tomato, zupa);

        ASSERT_PTR_EQ(UNIT_GET_SLICE(tomato), zupa);
        ASSERT_NULL(unit_has_dependency(tomato, UNIT_ATOM_IN_SLICE, sauce));
        ASSERT_NULL(unit_has_dependency(tomato, UNIT_ATOM_IN_SLICE, fruit));
        ASSERT_NOT_NULL(unit_has_dependency(tomato, UNIT_ATOM_IN_SLICE, zupa));

        ASSERT_NULL(unit_has_dependency(tomato, UNIT_ATOM_REFERENCES, sauce));
        ASSERT_NULL(unit_has_dependency(tomato, UNIT_ATOM_REFERENCES, fruit));
        ASSERT_NOT_NULL(unit_has_dependency(tomato, UNIT_ATOM_REFERENCES, zupa));

        ASSERT_NULL(unit_has_dependency(sauce, UNIT_ATOM_SLICE_OF, tomato));
        ASSERT_NULL(unit_has_dependency(fruit, UNIT_ATOM_SLICE_OF, tomato));
        ASSERT_NOT_NULL(unit_has_dependency(zupa, UNIT_ATOM_SLICE_OF, tomato));

        ASSERT_NULL(unit_has_dependency(sauce, UNIT_ATOM_REFERENCED_BY, tomato));
        ASSERT_NULL(unit_has_dependency(fruit, UNIT_ATOM_REFERENCED_BY, tomato));
        ASSERT_NOT_NULL(unit_has_dependency(zupa, UNIT_ATOM_REFERENCED_BY, tomato));
}

static Unit* reload_test_unit(Unit *u) {
        Manager *m = u->manager;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_free_ char *id = NULL;

        ASSERT_NOT_NULL(fds = fdset_new());
        ASSERT_OK(open_serialization_file("test-owned-directories", &f));
        ASSERT_OK(unit_serialize_state(u, f, fds, /* switching_root= */ false));
        ASSERT_OK(finish_serialization_file(f));
        unit_free(u);
        ASSERT_OK_POSITIVE(deserialize_read_line(f, &id));
        ASSERT_OK(manager_load_unit(m, id, /* path= */ NULL, /* e= */ NULL, &u));
        ASSERT_OK(unit_deserialize_state(u, f, fds, /* restore_owned_directories= */ true));
        return u;
}

static void wait_for_service_dead(Unit *u) {
        usec_t deadline = usec_add(now(CLOCK_MONOTONIC), 30 * USEC_PER_SEC);

        while (!IN_SET(SERVICE(u)->state, SERVICE_DEAD, SERVICE_FAILED)) {
                usec_t left = usec_sub_unsigned(deadline, now(CLOCK_MONOTONIC));
                ASSERT_GT(left, 0U);
                ASSERT_OK_POSITIVE(sd_event_run(u->manager->event, left));
        }
        ASSERT_EQ(SERVICE(u)->state, SERVICE_DEAD);
}

static int exit_test_manager(sd_event_source *source, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        m->objective = MANAGER_EXIT;
        return 0;
}

TEST(owned_directory_gc) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *exit_source = NULL;
        _cleanup_free_ char *file = NULL, *dir = NULL, *link = NULL;
        _cleanup_strv_free_ char **paths = NULL;
        const char *name = "test-owned-directory.service";
        Unit *u;
        int r;

        if (!have_cgroup_subroot)
                return (void) log_tests_skipped("No cgroup subroot for executing a test unit");

        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());
        ASSERT_NOT_NULL(file = path_join(runtime_dir, name));
        ASSERT_NOT_NULL(dir = path_join(runtime_dir, "data"));
        ASSERT_NOT_NULL(link = path_join(runtime_dir, "alias"));
        ASSERT_OK(setenv_unit_path(runtime_dir));
        ASSERT_OK(write_string_file(file, "[Unit]\nDefaultDependencies=no\n[Service]\n"
                                    "Type=oneshot\nExecStart=true\nStandardOutput=null\n"
                                    "RuntimeDirectory=data:alias\nRuntimeDirectoryPreserve=yes\n", WRITE_STRING_FILE_CREATE));
        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC|MANAGER_TEST_RUN_IGNORE_DEPENDENCIES, &m);
        if (manager_errno_skip_test(r))
                return (void) log_tests_skipped_errno(r, "manager_new");
        ASSERT_OK(r);
        ASSERT_OK(manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, /* named_listen_fds= */ NULL, /* root= */ NULL));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, name, /* path= */ NULL, LOG_ERR, &u));
        ASSERT_OK(unit_start(u, /* details= */ NULL));
        wait_for_service_dead(u);
        ASSERT_STRV_EQ_SET(u->owned_directories[EXEC_DIRECTORY_RUNTIME], dir, link);

        /* A replacement fragment contributes its configured paths without replacing the recorded paths. */
        ASSERT_OK(write_string_file(file, "[Service]\nExecStart=true\nRuntimeDirectory=replacement\n",
                                    WRITE_STRING_FILE_TRUNCATE));
        u = reload_test_unit(u);
        ASSERT_EQ(u->load_state, UNIT_LOADED);
        ASSERT_OK(unit_get_clean_directories(u, EXEC_CLEAN_RUNTIME, &paths));
        ASSERT_STRV_EQ_SET(paths, strjoina(runtime_dir, "/replacement"),
                           strjoina(runtime_dir, "/private/replacement"), dir, link);

        /* With no fragment left, only the paths the executor confirmed survive. */
        ASSERT_OK_ERRNO(unlink(file));
        u = reload_test_unit(u);
        ASSERT_EQ(u->load_state, UNIT_NOT_FOUND);
        ASSERT_STRV_EQ_SET(u->owned_directories[EXEC_DIRECTORY_RUNTIME], dir, link);
        ASSERT_FALSE(unit_may_gc(u));
        ASSERT_OK(unit_clean(u, EXEC_CLEAN_RUNTIME));
        wait_for_service_dead(u);

        ASSERT_EQ(unit_owned_directory_mask(u), EXEC_CLEAN_NONE);
        ASSERT_ERROR_ERRNO(access(dir, F_OK), ENOENT);
        ASSERT_ERROR_ERRNO(faccessat(AT_FDCWD, link, F_OK, AT_SYMLINK_NOFOLLOW), ENOENT);

        /* Let the manager deliver pending notifications and dispatch its GC and cleanup queues. */
        ASSERT_OK(sd_event_add_defer(m->event, &exit_source, exit_test_manager, m));
        ASSERT_OK(sd_event_source_set_priority(exit_source, SD_EVENT_PRIORITY_IDLE));
        ASSERT_OK_EQ(manager_loop(m), MANAGER_EXIT);
        ASSERT_NULL(manager_get_unit(m, name));
}

static int intro(void) {
        int r;

        r = enter_cgroup_subroot(/* ret_cgroup= */ NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");
        if (r < 0)
                log_debug_errno(r, "Failed to enter cgroup subroot, ignoring: %m");
        else
                have_cgroup_subroot = true;

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
