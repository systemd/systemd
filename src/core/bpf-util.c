/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if BPF_FRAMEWORK

#include "bpf-dlopen.h"
#include "bpf-util.h"
#include "cgroup-util.h"
#include "log.h"

bool bpf_supported(void) {
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0) {
                log_warning_errno(r, "Can't determine whether the unified hierarchy is used: %m");
                return (supported = false);
        }

        if (r == 0) {
                log_info_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Not running with unified cgroup hierarchy, BPF cgroup filters are not supported");
                return (supported = false);
        }

        r = dlopen_bpf();
        if (r < 0) {
                log_info_errno(r, "Failed to open libbpf, BPF cgroup filters disabled: %m");
                return (supported = false);
        }

        return (supported = true);
}
#endif
