/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "cgroup.h"
#include "manager.h"
#include "rm-rf.h"
#include "test-helper.h"
#include "tests.h"
#include "unit.h"

static int test_default_memory_low(void) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *root, *dml,
             *dml_passthrough, *dml_passthrough_empty, *dml_passthrough_set_dml, *dml_passthrough_set_ml,
             *dml_override, *dml_override_empty,
             *dml_discard, *dml_discard_empty, *dml_discard_set_ml;
        uint64_t dml_tree_default;
        int r;

        r = enter_cgroup_subroot();
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(set_unit_path(get_testdata_dir()) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());
        r = manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (IN_SET(r, -EPERM, -EACCES)) {
                log_error_errno(r, "manager_new: %m");
                return log_tests_skipped("cannot create manager");
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        /* dml.slice has DefaultMemoryLow=50. Beyond that, individual subhierarchies look like this:
         *
         * 1. dml-passthrough.slice sets MemoryLow=100. This should not affect its children, as only
         *    DefaultMemoryLow is propagated, not MemoryLow. As such, all leaf services should end up with
         *    memory.low as 50, inherited from dml.slice, *except* for dml-passthrough-set-ml.service, which
         *    should have the value of 0, as it has MemoryLow explicitly set.
         *
         *                                                  ┌───────────┐
         *                                                  │ dml.slice │
         *                                                  └─────┬─────┘
         *                                                  MemoryLow=100
         *                                            ┌───────────┴───────────┐
         *                                            │ dml-passthrough.slice │
         *                                            └───────────┬───────────┘
         *                    ┌───────────────────────────────────┼───────────────────────────────────┐
         *             no new settings                   DefaultMemoryLow=15                     MemoryLow=0
         *    ┌───────────────┴───────────────┐  ┌────────────────┴────────────────┐  ┌───────────────┴────────────────┐
         *    │ dml-passthrough-empty.service │  │ dml-passthrough-set-dml.service │  │ dml-passthrough-set-ml.service │
         *    └───────────────────────────────┘  └─────────────────────────────────┘  └────────────────────────────────┘
         *
         * 2. dml-override.slice sets DefaultMemoryLow=10. As such, dml-override-empty.service should also
         *    end up with a memory.low of 10. dml-override.slice should still have a memory.low of 50.
         *
         *            ┌───────────┐
         *            │ dml.slice │
         *            └─────┬─────┘
         *         DefaultMemoryLow=10
         *        ┌─────────┴──────────┐
         *        │ dml-override.slice │
         *        └─────────┬──────────┘
         *           no new settings
         *    ┌─────────────┴──────────────┐
         *    │ dml-override-empty.service │
         *    └────────────────────────────┘
         *
         * 3. dml-discard.slice sets DefaultMemoryLow= with no rvalue. As such,
         *    dml-discard-empty.service should end up with a value of 0.
         *    dml-discard-explicit-ml.service sets MemoryLow=70, and as such should have that override the
         *    reset DefaultMemoryLow value. dml-discard.slice should still have an eventual memory.low of 50.
         *
         *                           ┌───────────┐
         *                           │ dml.slice │
         *                           └─────┬─────┘
         *                         DefaultMemoryLow=
         *                       ┌─────────┴─────────┐
         *                       │ dml-discard.slice │
         *                       └─────────┬─────────┘
         *                  ┌──────────────┴───────────────┐
         *           no new settings                  MemoryLow=15
         *    ┌─────────────┴─────────────┐  ┌─────────────┴──────────────┐
         *    │ dml-discard-empty.service │  │ dml-discard-set-ml.service │
         *    └───────────────────────────┘  └────────────────────────────┘
         */
        assert_se(manager_load_startable_unit_or_warn(m, "dml.slice", NULL, &dml) >= 0);

        assert_se(manager_load_startable_unit_or_warn(m, "dml-passthrough.slice", NULL, &dml_passthrough) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough->slice) == dml);
        assert_se(manager_load_startable_unit_or_warn(m, "dml-passthrough-empty.service", NULL, &dml_passthrough_empty) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough_empty->slice) == dml_passthrough);
        assert_se(manager_load_startable_unit_or_warn(m, "dml-passthrough-set-dml.service", NULL, &dml_passthrough_set_dml) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough_set_dml->slice) == dml_passthrough);
        assert_se(manager_load_startable_unit_or_warn(m, "dml-passthrough-set-ml.service", NULL, &dml_passthrough_set_ml) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough_set_ml->slice) == dml_passthrough);

        assert_se(manager_load_startable_unit_or_warn(m, "dml-override.slice", NULL, &dml_override) >= 0);
        assert_se(UNIT_DEREF(dml_override->slice) == dml);
        assert_se(manager_load_startable_unit_or_warn(m, "dml-override-empty.service", NULL, &dml_override_empty) >= 0);
        assert_se(UNIT_DEREF(dml_override_empty->slice) == dml_override);

        assert_se(manager_load_startable_unit_or_warn(m, "dml-discard.slice", NULL, &dml_discard) >= 0);
        assert_se(UNIT_DEREF(dml_discard->slice) == dml);
        assert_se(manager_load_startable_unit_or_warn(m, "dml-discard-empty.service", NULL, &dml_discard_empty) >= 0);
        assert_se(UNIT_DEREF(dml_discard_empty->slice) == dml_discard);
        assert_se(manager_load_startable_unit_or_warn(m, "dml-discard-set-ml.service", NULL, &dml_discard_set_ml) >= 0);
        assert_se(UNIT_DEREF(dml_discard_set_ml->slice) == dml_discard);

        root = UNIT_DEREF(dml->slice);
        assert_se(!UNIT_ISSET(root->slice));

        assert_se(unit_get_ancestor_memory_low(root) == CGROUP_LIMIT_MIN);

        assert_se(unit_get_ancestor_memory_low(dml) == CGROUP_LIMIT_MIN);
        dml_tree_default = unit_get_cgroup_context(dml)->default_memory_low;
        assert_se(dml_tree_default == 50);

        assert_se(unit_get_ancestor_memory_low(dml_passthrough) == 100);
        assert_se(unit_get_ancestor_memory_low(dml_passthrough_empty) == dml_tree_default);
        assert_se(unit_get_ancestor_memory_low(dml_passthrough_set_dml) == 50);
        assert_se(unit_get_ancestor_memory_low(dml_passthrough_set_ml) == 0);

        assert_se(unit_get_ancestor_memory_low(dml_override) == dml_tree_default);
        assert_se(unit_get_ancestor_memory_low(dml_override_empty) == 10);

        assert_se(unit_get_ancestor_memory_low(dml_discard) == dml_tree_default);
        assert_se(unit_get_ancestor_memory_low(dml_discard_empty) == CGROUP_LIMIT_MIN);
        assert_se(unit_get_ancestor_memory_low(dml_discard_set_ml) == 15);

        return 0;
}

int main(int argc, char* argv[]) {
        int rc = EXIT_SUCCESS;

        test_setup_logging(LOG_DEBUG);

        TEST_REQ_RUNNING_SYSTEMD(rc = test_default_memory_low());

        return rc;
}
