/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2013 David Strauss

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>

#include "macro.h"
#include "manager.h"
#include "rm-rf.h"
#include "string-util.h"
#include "test-helper.h"
#include "tests.h"
#include "unit.h"

static int test_cgroup_mask(void) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *son, *daughter, *parent, *root, *grandchild, *parent_deep;
        FILE *serial = NULL;
        FDSet *fdset = NULL;
        int r;

        r = enter_cgroup_subroot();
        if (r == -ENOMEDIUM) {
                puts("Skipping test: cgroupfs not available");
                return EXIT_TEST_SKIP;
        }

        /* Prepare the manager. */
        assert_se(set_unit_path(get_testdata_dir("")) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());
        r = manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (IN_SET(r, -EPERM, -EACCES)) {
                puts("manager_new: Permission denied. Skipping test.");
                return EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);

        /* Turn off all kinds of default accouning, so that we can
         * verify the masks resulting of our configuration and nothing
         * else. */
        m->default_cpu_accounting =
                m->default_memory_accounting =
                m->default_blockio_accounting =
                m->default_io_accounting =
                m->default_tasks_accounting = false;
        m->default_tasks_max = (uint64_t) -1;

        assert_se(r >= 0);
        assert_se(manager_startup(m, serial, fdset) >= 0);

        /* Load units and verify hierarchy. */
        assert_se(manager_load_unit(m, "parent.slice", NULL, NULL, &parent) >= 0);
        assert_se(manager_load_unit(m, "son.service", NULL, NULL, &son) >= 0);
        assert_se(manager_load_unit(m, "daughter.service", NULL, NULL, &daughter) >= 0);
        assert_se(manager_load_unit(m, "grandchild.service", NULL, NULL, &grandchild) >= 0);
        assert_se(manager_load_unit(m, "parent-deep.slice", NULL, NULL, &parent_deep) >= 0);
        assert_se(parent->load_state == UNIT_LOADED);
        assert_se(son->load_state == UNIT_LOADED);
        assert_se(daughter->load_state == UNIT_LOADED);
        assert_se(grandchild->load_state == UNIT_LOADED);
        assert_se(parent_deep->load_state == UNIT_LOADED);
        assert_se(UNIT_DEREF(son->slice) == parent);
        assert_se(UNIT_DEREF(daughter->slice) == parent);
        assert_se(UNIT_DEREF(parent_deep->slice) == parent);
        assert_se(UNIT_DEREF(grandchild->slice) == parent_deep);
        root = UNIT_DEREF(parent->slice);

        /* Verify per-unit cgroups settings. */
        assert_se(unit_get_own_mask(son) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT));
        assert_se(unit_get_own_mask(daughter) == 0);
        assert_se(unit_get_own_mask(grandchild) == 0);
        assert_se(unit_get_own_mask(parent_deep) == CGROUP_MASK_MEMORY);
        assert_se(unit_get_own_mask(parent) == (CGROUP_MASK_IO | CGROUP_MASK_BLKIO));
        assert_se(unit_get_own_mask(root) == 0);

        /* Verify aggregation of member masks */
        assert_se(unit_get_members_mask(son) == 0);
        assert_se(unit_get_members_mask(daughter) == 0);
        assert_se(unit_get_members_mask(grandchild) == 0);
        assert_se(unit_get_members_mask(parent_deep) == 0);
        assert_se(unit_get_members_mask(parent) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_MEMORY));
        assert_se(unit_get_members_mask(root) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of sibling masks. */
        assert_se(unit_get_siblings_mask(son) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_MEMORY));
        assert_se(unit_get_siblings_mask(daughter) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_MEMORY));
        assert_se(unit_get_siblings_mask(grandchild) == 0);
        assert_se(unit_get_siblings_mask(parent_deep) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_MEMORY));
        assert_se(unit_get_siblings_mask(parent) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        assert_se(unit_get_siblings_mask(root) == (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of target masks. */
        assert_se(unit_get_target_mask(son) == ((CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        assert_se(unit_get_target_mask(daughter) == ((CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        assert_se(unit_get_target_mask(grandchild) == 0);
        assert_se(unit_get_target_mask(parent_deep) == ((CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        assert_se(unit_get_target_mask(parent) == ((CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        assert_se(unit_get_target_mask(root) == ((CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY) & m->cgroup_supported));

        return 0;
}

static void test_cg_mask_to_string_one(CGroupMask mask, const char *t) {
        _cleanup_free_ char *b = NULL;

        assert_se(cg_mask_to_string(mask, &b) >= 0);
        assert_se(streq_ptr(b, t));
}

static void test_cg_mask_to_string(void) {
        test_cg_mask_to_string_one(0, NULL);
        test_cg_mask_to_string_one(_CGROUP_MASK_ALL, "cpu cpuacct io blkio memory devices pids");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU, "cpu");
        test_cg_mask_to_string_one(CGROUP_MASK_CPUACCT, "cpuacct");
        test_cg_mask_to_string_one(CGROUP_MASK_IO, "io");
        test_cg_mask_to_string_one(CGROUP_MASK_BLKIO, "blkio");
        test_cg_mask_to_string_one(CGROUP_MASK_MEMORY, "memory");
        test_cg_mask_to_string_one(CGROUP_MASK_DEVICES, "devices");
        test_cg_mask_to_string_one(CGROUP_MASK_PIDS, "pids");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU|CGROUP_MASK_CPUACCT, "cpu cpuacct");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU|CGROUP_MASK_PIDS, "cpu pids");
        test_cg_mask_to_string_one(CGROUP_MASK_CPUACCT|CGROUP_MASK_PIDS, "cpuacct pids");
        test_cg_mask_to_string_one(CGROUP_MASK_DEVICES|CGROUP_MASK_PIDS, "devices pids");
        test_cg_mask_to_string_one(CGROUP_MASK_IO|CGROUP_MASK_BLKIO, "io blkio");
}

int main(int argc, char* argv[]) {
        int rc = 0;

        log_parse_environment();
        log_open();

        TEST_REQ_RUNNING_SYSTEMD(rc = test_cgroup_mask());
        test_cg_mask_to_string();

        return rc;
}
