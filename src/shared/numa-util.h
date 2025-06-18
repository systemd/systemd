/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cpu-set-util.h"
#include "forward.h"
#include "missing_syscall.h"

bool mpol_is_valid(int t);

typedef struct NUMAPolicy {
        /* Always use numa_policy_get_type() to read the value */
        int type;
        CPUSet nodes;
} NUMAPolicy;

int numa_policy_get_type(const NUMAPolicy *p);

bool numa_policy_is_valid(const NUMAPolicy *p);

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
