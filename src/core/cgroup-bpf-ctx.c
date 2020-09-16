/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bpf-program.h"
#include "cgroup-bpf-ctx.h"
#include "cgroup.h"
#include "memory-util.h"
#include "strv.h"
#include "string-util.h"
#include "path-util.h"
#include "strv.h"

int bpffs_program_from_string(const char *str, enum bpf_attach_type *ret_attach_type, char **ret_bpffs_path) {
        _cleanup_strv_free_ char **parts = NULL;
        _cleanup_free_ char *dup = NULL;
        int attach_type;

        assert(str);
        assert(ret_bpffs_path);
        assert(ret_attach_type);

        parts = strv_split(str, ":");
        if (!parts)
                return log_oom();

        if (strv_length(parts) < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "Unexpected BPF program string format %s", str);

        dup = strdup(parts[1]);
        if (!dup)
                return log_oom();

        attach_type = bpf_cgroup_attach_type_from_string(parts[0]);
        if (attach_type < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown BPF attach type=%s", parts[0]);

        *ret_attach_type = (enum bpf_attach_type) attach_type;
        *ret_bpffs_path = TAKE_PTR(dup);
        return 0;
}

int bpffs_program_to_string(enum bpf_attach_type attach_type, const char *bpffs_path, char **ret_str) {
        _cleanup_free_ char *p = NULL;
        const char *s = NULL;

        assert(bpffs_path);
        assert(ret_str);

        s = bpf_cgroup_attach_type_to_string(attach_type);

        /* Likely should update bpf_cgroup_attach_type_table with new mapping. */
        if (!s)
                s = "unknown";

        p = strjoin(s, ":", bpffs_path);
        if (!p)
                return log_oom();

        *ret_str = TAKE_PTR(p);
        return 0;
}

int cgroup_add_bpffs_program(CGroupContext *c, enum bpf_attach_type attach_type, const char *bpffs_path) {
        _cleanup_free_ CGroupBPFFsProgram *p = NULL;
        _cleanup_free_ char *dup = NULL;
        int r;

        assert(c);
        assert(bpffs_path);

        if (cgroup_contains_bpffs_program(c, attach_type, bpffs_path)) {
                _cleanup_free_ char *s = NULL;

                r = bpffs_program_to_string(attach_type, bpffs_path, &s);
                if (r < 0)
                        return r;

                return log_warning_errno(SYNTHETIC_ERRNO(EEXIST),
                                "BPF program %s is already specified in cgroup context", s);
        }

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
