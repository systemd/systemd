/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering

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

#include "test-helper.h"
#include "random-util.h"
#include "alloc-util.h"
#include "cgroup-util.h"

int enter_cgroup_subroot(void) {
        _cleanup_free_ char *cgroup_root = NULL, *cgroup_subroot = NULL;
        CGroupMask supported;
        int r;

        r = cg_pid_get_path(NULL, 0, &cgroup_root);
        if (r == -ENOMEDIUM)
                return log_warning_errno(r, "cg_pid_get_path(NULL, 0, ...) failed: %m");
        assert(r >= 0);

        assert_se(asprintf(&cgroup_subroot, "%s/%" PRIx64, cgroup_root, random_u64()) >= 0);
        assert_se(cg_mask_supported(&supported) >= 0);

        /* If this fails, then we don't mind as the later cgroup operations will fail too, and it's fine if we handle
         * any errors at that point. */

        r = cg_create_everywhere(supported, _CGROUP_MASK_ALL, cgroup_subroot);
        if (r < 0)
                return r;

        return cg_attach_everywhere(supported, cgroup_subroot, 0, NULL, NULL);
}
