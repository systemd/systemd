/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sched.h>

#include "macro.h"

#ifdef __NCPUBITS
#define CPU_SIZE_TO_NUM(n) ((n) * __NCPUBITS)
#else
#define CPU_SIZE_TO_NUM(n) ((n) * sizeof(cpu_set_t) * 8)
#endif

DEFINE_TRIVIAL_CLEANUP_FUNC(cpu_set_t*, CPU_FREE);
#define _cleanup_cpu_free_ _cleanup_(CPU_FREEp)

static inline cpu_set_t* cpu_set_mfree(cpu_set_t *p) {
        if (p)
                CPU_FREE(p);
        return NULL;
}

cpu_set_t* cpu_set_malloc(unsigned *ncpus);

int parse_cpu_set_internal(const char *rvalue, cpu_set_t **cpu_set, bool warn, const char *unit, const char *filename, unsigned line, const char *lvalue);

static inline int parse_cpu_set_and_warn(const char *rvalue, cpu_set_t **cpu_set, const char *unit, const char *filename, unsigned line, const char *lvalue) {
        assert(lvalue);

        return parse_cpu_set_internal(rvalue, cpu_set, true, unit, filename, line, lvalue);
}

static inline int parse_cpu_set(const char *rvalue, cpu_set_t **cpu_set){
        return parse_cpu_set_internal(rvalue, cpu_set, false, NULL, NULL, 0, NULL);
}
