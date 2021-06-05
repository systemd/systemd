/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cpu-set-util.h"
#include "missing_syscall.h"

static inline bool mpol_is_valid(int t) {
        return t >= MPOL_DEFAULT && t <= MPOL_LOCAL;
}

typedef struct NUMAPolicy {
        /* Always use numa_policy_get_type() to read the value */
        int type;
        CPUSet nodes;
} NUMAPolicy;

bool numa_policy_is_valid(const NUMAPolicy *p);

static inline int numa_policy_get_type(const NUMAPolicy *p) {
        return p->type < 0 ? (p->nodes.set ? MPOL_PREFERRED : -1) : p->type;
}

static inline void numa_policy_reset(NUMAPolicy *p) {
        assert(p);
        cpu_set_reset(&p->nodes);
        p->type = -1;
}

int apply_numa_policy(const NUMAPolicy *policy);
int numa_to_cpu_set(const NUMAPolicy *policy, CPUSet *set);

int numa_mask_add_all(CPUSet *mask);

const char* mpol_to_string(int i) _const_;
int mpol_from_string(const char *s) _pure_;
