/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bpffs-program.h"
#include "cgroup-bpf-ctx.h"

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(bpf_prog_hash_ops, void, trivial_hash_func, trivial_compare_func, BPFProgram, bpf_program_unref);

static int load_programs(Unit *u, const CGroupContext *c, Hashmap *progs_by_id) {
        CGroupBPFFsProgram *p;
        int r;

        assert(u);
        assert(c);
        assert(progs_by_id);

        LIST_FOREACH(prog, p, c->bpffs_programs) {
                _cleanup_(bpf_program_unrefp) BPFProgram *prog = NULL;

                r = bpf_program_new_from_bpffs_path(p->bpffs_path, p->attach_type, &prog);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Loading of BPF program %s failed: %m", p->bpffs_path);

                r = hashmap_put(progs_by_id, p, prog);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Can't put program to hashmap: %m");

                TAKE_PTR(prog);
        }

        return 0;
}

static int attach_programs(Unit *u, const char *path, Hashmap *progs_by_id, Set **set_installed, uint32_t attach_flags) {
        CGroupBPFFsProgram *id;
        BPFProgram *prog;
        int r;

        assert(u);
        assert(set_installed);

        HASHMAP_FOREACH_KEY(prog, id, progs_by_id) {
                r = bpf_program_cgroup_attach(prog, id->attach_type, path, attach_flags);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Attaching custom egress BPF program to cgroup %s failed: %m", path);

                r = set_ensure_put(set_installed, &bpf_prog_hash_ops, prog);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Can't add program to BPF program set: %m");

                bpf_program_ref(prog);
        }

        return 0;
}

int bpffs_program_install(Unit *u) {
        _cleanup_free_ char *cgroup_path = NULL;
        /* BPFProgram is identified by CGroupBPFFsProgram key. */
        _cleanup_hashmap_free_ Hashmap *progs_by_id = NULL;
        CGroupContext *cc;
        int r;

        assert(u);

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return 0;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &cgroup_path);
        if (r < 0)
                return r;

        if (LIST_IS_EMPTY(cc->bpffs_programs) && set_isempty(u->bpf_custom_installed))
                return 0;

        progs_by_id = hashmap_new(&bpf_prog_hash_ops);
        if (!progs_by_id)
                return log_oom();

        r = load_programs(u, cc, progs_by_id);
        if (r < 0)
                return log_unit_error_errno(u, r, "Loading programs from bpffs failed: %m");

        /* Programs are detached in bpf_program_free. */
        set_clear(u->bpf_custom_installed);

        r = attach_programs(u, cgroup_path, progs_by_id, &u->bpf_custom_installed, BPF_F_ALLOW_MULTI);
        if (r < 0)
                return log_unit_error_errno(u, r, "Attaching bpffs program to cgroup %s failed: %m", cgroup_path);

        return 0;
}
