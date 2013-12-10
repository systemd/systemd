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
        Manager *m;
        Unit *son, *daughter, *parent, *root;
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
        assert(parent->load_state == UNIT_LOADED);
        assert(son->load_state == UNIT_LOADED);
        assert(daughter->load_state == UNIT_LOADED);
        assert(UNIT_DEREF(son->slice) == parent);
        assert(UNIT_DEREF(daughter->slice) == parent);
        root = UNIT_DEREF(parent->slice);

        /* Verify per-unit cgroups settings. */
        assert(cgroup_context_get_mask(unit_get_cgroup_context(son)) == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(cgroup_context_get_mask(unit_get_cgroup_context(daughter)) == 0);
        assert(cgroup_context_get_mask(unit_get_cgroup_context(parent)) == CGROUP_BLKIO);
        assert(cgroup_context_get_mask(unit_get_cgroup_context(root)) == 0);

        /* Verify aggregation of controller masks. */
        assert(son->cgroup_members_mask == (CGROUP_CPU | CGROUP_CPUACCT));
        assert(daughter->cgroup_members_mask == 0);
        assert(parent->cgroup_members_mask == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_BLKIO));
        assert(root->cgroup_members_mask == (CGROUP_CPU | CGROUP_CPUACCT | CGROUP_BLKIO));

        manager_free(m);

        return 0;
}

int main(int argc, char* argv[]) {
        int rc = 0;
        TEST_REQ_RUNNING_SYSTEMD(rc = test_cgroup_mask());
        return rc;
}
