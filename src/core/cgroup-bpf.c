/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "cgroup-bpf.h"
#include "unit.h"

#if HAVE_LIBBPF

#include "bpf-program-v2.h"
int cgroup_bpf_attach_programs(Unit *u, const Set *progs, uint32_t attach_flags) {
        _cleanup_free_ char *cgroup_path = NULL;
        BPFProgramV2 *prog;
        int r;

        assert(u);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to get cgroup path: %m");

        SET_FOREACH(prog, progs) {
                r = bpf_program_v2_cgroup_attach(prog, cgroup_path, attach_flags);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to attach program to cgroup '%s': %m", cgroup_path);
        }

        return 0;
}

int cgroup_bpf_detach_programs(Unit *u, const Set *progs) {
        _cleanup_free_ char *cgroup_path = NULL;
        BPFProgramV2 *prog;
        int err = 0;
        int r;

        assert(u);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to get cgroup path: %m");

        SET_FOREACH(prog, progs) {
                r = bpf_program_v2_cgroup_detach(prog, cgroup_path);
                if (r < 0) {
                        if (!err)
                                err = errno;
                        log_unit_warning_errno(u, r, "Failed to detach program from cgroup '%s': %m", cgroup_path);
                }
        }

        return -err;
}

#else

int cgroup_bpf_attach_programs(Unit *u, const Set *progs, uint32_t attach_flags) {
        return log_unit_warning_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                        "libbpf dependency is not satisfied, attach BPF v2 is not supported");
}

int cgroup_bpf_detach_programs(Unit *u, const Set *progs) {
        return log_unit_warning_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                        "libbpf dependency is not satisfied, detach BPF v2 is not supported");
}

#endif
