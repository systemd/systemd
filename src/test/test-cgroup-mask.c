/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

#include "manager.h"
#include "unit.h"
#include "util.h"
#include "macro.h"
#include "test-helper.h"

static int test_cgroup_mask(void) {
        Manager *m = NULL;
        Unit *son, *daughter, *parent, *root, *grandchild, *parent_deep;
        FILE *serial = NULL;
        FDSet *fdset = NULL;
        int r;
        const char *dir = TEST_DIR;

        /* Prepare the manager. */
        assert_se(set_unit_path(dir) >= 0);
        r = manager_new(SYSTEMD_USER, &m);
        if (r == -EPERM || r == -EACCES) {
                puts("manager_new: Permission denied. Skipping test.");
                return EXIT_TEST_SKIP;
        }
        assert(r >= 0);
        assert_se(manager_startup(m, serial, fdset) >= 0);

        /* Load units and verify hierarchy. */
        assert_se(manager_load_unit(m, "parent.slice", NULL, NULL, &parent) >= 0);
        assert_se(manager_load_unit(m, "son.service", NULL, NULL, &son) >= 0);
        assert_se(manager_load_unit(m, "daughter.service", NULL, NULL, &daughter) >= 0);
        assert_se(manager_load_unit(m, "grandchild.service", NULL, NULL, &grandchild) >= 0);
        assert_se(manager_load_unit(m, "parent-deep.slice", NULL, NULL, &parent_deep) >= 0);
        assert(parent->load_state == UNIT_LOADED);
        assert(son->load_state == UNIT_LOADED);
        assert(daughter->load_state == UNIT_LOADED);
        assert(grandchild->load_state == UNIT_LOADED);
        assert(parent_deep->load_state == UNIT_LOADED);
        assert(UNIT_DEREF(son->slice) == parent);
        assert(UNIT_DEREF(daughter->slice) == parent);
        assert(UNIT_DEREF(parent_deep->slice) == parent);
        assert(UNIT_DEREF(grandchild->slice) == parent_deep);
        root = UNIT_DEREF(parent->slice);

        /* Verify per-unit cgroups settings. */
        assert(unit_get_cgroup_mask(son) == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(unit_get_cgroup_mask(daughter) == 0);
        assert(unit_get_cgroup_mask(grandchild) == 0);
        assert(unit_get_cgroup_mask(parent_deep) == CGROUP_MEMORY);
        assert(unit_get_cgroup_mask(parent) == CGROUP_BLKIO);
        assert(unit_get_cgroup_mask(root) == 0);

        /* Verify aggregation of member masks */
        assert(unit_get_members_mask(son) == 0);
        assert(unit_get_members_mask(daughter) == 0);
        assert(unit_get_members_mask(grandchild) == 0);
        assert(unit_get_members_mask(parent_deep) == 0);
        assert(unit_get_members_mask(parent) == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_MEMORY));
        assert(unit_get_members_mask(root) == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_BLKIO | CGROUP_MEMORY));

        /* Verify aggregation of sibling masks. */
        assert(unit_get_siblings_mask(son) == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(unit_get_siblings_mask(daughter) == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(unit_get_siblings_mask(grandchild) == 0);
        assert(unit_get_siblings_mask(parent_deep) == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(unit_get_siblings_mask(parent) == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_BLKIO));
        assert(unit_get_siblings_mask(root) == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_BLKIO));

        /* Verify aggregation of target masks. */
        assert(unit_get_target_mask(son) == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(unit_get_target_mask(daughter) == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(unit_get_target_mask(grandchild) == 0);
        assert(unit_get_target_mask(parent_deep) == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_MEMORY));
        assert(unit_get_target_mask(parent) == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_BLKIO | CGROUP_MEMORY));
        assert(unit_get_target_mask(root) == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_BLKIO | CGROUP_MEMORY));

        manager_free(m);

        return 0;
}

int main(int argc, char* argv[]) {
        int rc = 0;
        TEST_REQ_RUNNING_SYSTEMD(rc = test_cgroup_mask());
        return rc;
}
