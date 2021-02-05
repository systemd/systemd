/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bpf-foreign.h"
#include "cgroup.h"
#include "fd-util.h"
#include "memory-util.h"
#include "set.h"
#include "strv.h"
#include "string-util.h"
#include "path-util.h"

typedef struct BPFForeignKey BPFForeignKey;
struct BPFForeignKey {
        uint32_t prog_id;
        uint32_t attach_type;
};

static int bpf_foreign_key_new(uint32_t prog_id,
                enum bpf_attach_type attach_type,
                BPFForeignKey **ret) {
        _cleanup_free_ BPFForeignKey *p = NULL;

        assert(ret);

        p = new(BPFForeignKey, 1);
        if (!p)
                return -ENOMEM;

        *p = (BPFForeignKey) {
                .prog_id = prog_id,
                .attach_type = attach_type,
        };

        *ret = TAKE_PTR(p);

        return 0;
}

static int bpf_foreign_key_compare_func(const BPFForeignKey *a, const BPFForeignKey *b) {
        int r = CMP(a->prog_id, b->prog_id);
        if (r != 0)
                return r;

        return CMP(a->attach_type, b->attach_type);
}

static void bpf_foreign_key_hash_func(const BPFForeignKey *p, struct siphash *h) {
        siphash24_compress(&p->prog_id, sizeof(p->prog_id), h);
        siphash24_compress(&p->attach_type, sizeof(p->attach_type), h);
}

DEFINE_PRIVATE_HASH_OPS_FULL(bpf_foreign_next_by_key_hash_ops,
                BPFForeignKey, bpf_foreign_key_hash_func, bpf_foreign_key_compare_func, free,
                BPFProgram, bpf_program_unref);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(bpf_foreign_installed_hash_ops,
                void, trivial_hash_func, trivial_compare_func,
                BPFProgram, bpf_program_unref);

static int attach_programs(Unit *u, const char *path, Hashmap* foreign_by_key, Set **installed, uint32_t attach_flags) {
        const BPFForeignKey *key;
        BPFProgram *prog;
        int r;

        assert(u);
        assert(installed);

        HASHMAP_FOREACH_KEY(prog, key, foreign_by_key) {
                r = bpf_program_cgroup_attach(prog, key->attach_type, path, attach_flags);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Attaching foreign BPF program to cgroup %s failed: %m", path);

                r = set_ensure_put(installed, &bpf_foreign_installed_hash_ops, prog);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Can't add foreign BPF program to installed set: %m");

                bpf_program_ref(prog);
        }

        return 0;
}

int bpf_foreign_program_from_string(const char *str, enum bpf_attach_type *ret_attach_type, char **ret_bpffs_path) {
        _cleanup_free_ char *word = NULL;
        _cleanup_free_ char *dup = NULL;
        int attach_type;
        int r;

        assert(str);
        assert(ret_bpffs_path);
        assert(ret_attach_type);

        r = extract_first_word(&str, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();

        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse '%s'", str);

        if (!path_is_normalized(str))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path='%s' is not normalized", str);

        dup = strdup(str);
        if (!dup)
                return log_oom();

        attach_type = bpf_cgroup_attach_type_from_string(word);
        if (attach_type < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown BPF attach type=%s", word);

        *ret_attach_type = (enum bpf_attach_type) attach_type;
        *ret_bpffs_path = TAKE_PTR(dup);

        return 0;
}

int bpf_foreign_program_to_string(enum bpf_attach_type attach_type, const char *bpffs_path, char **ret_str) {
        _cleanup_free_ char *p = NULL, *x = NULL;
        const char *s = NULL;

        assert(bpffs_path);
        assert(ret_str);

        s = bpf_cgroup_attach_type_to_string(attach_type);

        /* Likely should update bpf_cgroup_attach_type_table with new mapping. */
        if (!s) {
                if (asprintf(&x, "unknown(%d)", attach_type) < 0)
                        return log_oom();
                s = x;
        }

        p = strjoin(s, ":", bpffs_path);
        if (!p)
                return log_oom();

        *ret_str = TAKE_PTR(p);
        return 0;
}

int bpf_foreign_prepare(Unit *u, enum bpf_attach_type attach_type, const char *bpffs_path) {
        _cleanup_(bpf_program_unrefp) BPFProgram *prog = NULL;
        _cleanup_free_ BPFForeignKey *key = NULL;
        uint32_t prog_id;
        int r;

        assert(u);
        assert(bpffs_path);

        r = bpf_program_new_from_bpffs_path(bpffs_path, &prog);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to create foreign BPFProgram: %m");

        r = bpf_program_get_id_by_fd(prog->kernel_fd, &prog_id);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to get BPF program id by fd: %m");

        r = bpf_foreign_key_new(prog_id, attach_type, &key);
        if (r < 0)
                return log_unit_error_errno(u, r,
                                "Failed to create foreign BPF program key from path '%s': %m", bpffs_path);

        if (hashmap_contains(u->bpf_foreign_next_by_key, key)) {
                log_unit_warning_errno(u, SYNTHETIC_ERRNO(EEXIST),
                                "Foreign BPF program already exists, ignoring: %m");
                return 0;
        }

        r = hashmap_ensure_put(&u->bpf_foreign_next_by_key, &bpf_foreign_next_by_key_hash_ops, key, prog);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to put foreign BPFProgram into map: %m");

        TAKE_PTR(key);
        TAKE_PTR(prog);

        return 0;
}

int bpf_foreign_install(Unit *u) {
        _cleanup_free_ char *cgroup_path = NULL;
        int r;

        assert(u);

        if (!unit_get_cgroup_context(u))
                return 0;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &cgroup_path);
        if (r < 0)
                return r;

        set_clear(u->bpf_foreign_installed);
        r = attach_programs(u, cgroup_path, u->bpf_foreign_next_by_key, &u->bpf_foreign_installed, BPF_F_ALLOW_MULTI);
        if (r < 0)
                  log_unit_error_errno(u, r, "Failed to install foreign BPF programs: %m");

        bpf_foreign_reset(u);

        return r;
}

void bpf_foreign_reset(Unit *u) {
        assert(u);

        hashmap_clear(u->bpf_foreign_next_by_key);
}

void bpf_foreign_free(Unit *u) {
        if (u) {
                hashmap_free(u->bpf_foreign_next_by_key);
                set_free(u->bpf_foreign_installed);
        }
}
