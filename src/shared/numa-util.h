/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/mempolicy.h>

#include "cpu-set-util.h"
#include "shared-forward.h"

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
        cpu_set_done(&p->nodes);
        p->type = -1;
}

int apply_numa_policy(const NUMAPolicy *policy);
int numa_to_cpu_set(const NUMAPolicy *policy, CPUSet *ret);

int numa_mask_add_all(CPUSet *mask);

int numa_get_node_from_cpu(unsigned cpu, unsigned *ret);
int numa_node_get_cpus(int node, CPUSet *ret);

DECLARE_STRING_TABLE_LOOKUP(mpol, int);
