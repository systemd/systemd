/* SPDX-License-Identifier: LGPL-2.1+ */

#include "cgroup-bpf-ctx.h"
#include "cgroup.h"
#include "memory-util.h"
#include "strv.h"
#include "string-util.h"
#include "path-util.h"

int cgroup_add_bpffs_program(CGroupContext *c, enum bpf_attach_type attach_type, const char *bpffs_path) {
        _cleanup_free_ CGroupBPFFsProgram *p = NULL;
        _cleanup_free_ char *dup = NULL;

        assert(c);
        assert(bpffs_path);

        if (cgroup_contains_bpffs_program(c, attach_type, bpffs_path))
                return log_warning_errno(SYNTHETIC_ERRNO(EEXIST),
                                "BPF program %s is already specified in cgroup context", bpffs_path);

        dup = strdup(bpffs_path);
        if (!dup)
                return log_oom();

        p = new(CGroupBPFFsProgram, 1);
        if (!p)
                return log_oom();

        *p = (CGroupBPFFsProgram) {
                .attach_type = attach_type,
                .bpffs_path = TAKE_PTR(dup),
        };

        LIST_PREPEND(prog, c->bpffs_programs, TAKE_PTR(p));

        return 0;
}

bool cgroup_contains_bpffs_program(
                CGroupContext *c, enum bpf_attach_type attach_type, const char *bpffs_path) {
        CGroupBPFFsProgram *p;

        assert(c);
        assert(bpffs_path);

        LIST_FOREACH(prog, p, c->bpffs_programs)
                if (attach_type == p->attach_type && path_equal(bpffs_path, p->bpffs_path))
                        return true;

        return false;
}

void cgroup_context_free_bpffs_program(CGroupContext *c, CGroupBPFFsProgram *p) {
        assert(c);
        assert(p);

        LIST_REMOVE(prog, c->bpffs_programs, p);
        free(p->bpffs_path);
        free(p);
}
