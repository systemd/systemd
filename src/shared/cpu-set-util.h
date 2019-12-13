/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sched.h>

#include "macro.h"
#include "missing_syscall.h"

/* This wraps the libc interface with a variable to keep the allocated size. */
typedef struct CPUSet {
        cpu_set_t *set;
        size_t allocated; /* in bytes */
} CPUSet;

static inline void cpu_set_reset(CPUSet *a) {
        assert((a->allocated > 0) == !!a->set);
        if (a->set)
                CPU_FREE(a->set);
        *a = (CPUSet) {};
}

int cpu_set_add_all(CPUSet *a, const CPUSet *b);

char* cpu_set_to_string(const CPUSet *a);
char *cpu_set_to_range_string(const CPUSet *a);
int cpu_set_realloc(CPUSet *cpu_set, unsigned ncpus);

int parse_cpu_set_full(
                const char *rvalue,
                CPUSet *cpu_set,
                bool warn,
                const char *unit,
                const char *filename, unsigned line,
                const char *lvalue);
int parse_cpu_set_extend(
                const char *rvalue,
                CPUSet *old,
                bool warn,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue);

static inline int parse_cpu_set(const char *rvalue, CPUSet *cpu_set){
        return parse_cpu_set_full(rvalue, cpu_set, false, NULL, NULL, 0, NULL);
}

int cpu_set_to_dbus(const CPUSet *set, uint8_t **ret, size_t *allocated);
int cpu_set_from_dbus(const uint8_t *bits, size_t size, CPUSet *set);

int cpus_in_affinity_mask(void);

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

const char* mpol_to_string(int i) _const_;
int mpol_from_string(const char *s) _pure_;
