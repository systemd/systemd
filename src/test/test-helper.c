/* SPDX-License-Identifier: LGPL-2.1+ */

#include "test-helper.h"
#include "random-util.h"
#include "alloc-util.h"
#include "cgroup-util.h"
#include "string-util.h"

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

/* https://docs.travis-ci.com/user/environment-variables#default-environment-variables */
bool is_run_on_travis_ci(void) {
        return streq_ptr(getenv("TRAVIS"), "true");
}
