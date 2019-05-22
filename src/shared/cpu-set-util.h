/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sched.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(cpu_set_t*, CPU_FREE);
#define _cleanup_cpu_free_ _cleanup_(CPU_FREEp)

static inline cpu_set_t* cpu_set_mfree(cpu_set_t *p) {
        if (p)
                CPU_FREE(p);
        return NULL;
}

cpu_set_t* cpu_set_malloc(unsigned *ncpus);
int cpu_set_add_all(cpu_set_t **cpu_set, size_t *allocated, const cpu_set_t *b, size_t b_allocated);

char* cpu_set_to_string(const cpu_set_t *set, size_t setsize);
int parse_cpu_set_full(
                const char *rvalue,
                cpu_set_t **cpu_set,
                size_t *allocated,
                bool warn,
                const char *unit,
                const char *filename, unsigned line,
                const char *lvalue);
int parse_cpu_set_extend(
                const char *rvalue,
                cpu_set_t **old,
                size_t *old_allocated,
                bool warn,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue);

static inline int parse_cpu_set(const char *rvalue, cpu_set_t **cpu_set, size_t *allocated){
        return parse_cpu_set_full(rvalue, cpu_set, allocated, false, NULL, NULL, 0, NULL);
}

int cpu_set_to_dbus(const cpu_set_t *set, size_t allocated, char **ret);
int cpu_set_from_dbus(const char *bits, size_t size, cpu_set_t **set, size_t *allocated);
