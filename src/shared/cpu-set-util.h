/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sched.h>

#include "conf-parser-forward.h"
#include "forward.h"

/* This wraps the libc interface with a variable to keep the allocated size. */
typedef struct CPUSet {
        cpu_set_t *set;
        size_t allocated; /* in bytes */
} CPUSet;

void cpu_set_done(CPUSet *c);
#define cpu_set_done_and_replace(a, b)                      \
        ({                                                  \
                CPUSet *_a = &(a), *_b = &(b);              \
                cpu_set_done(_a);                           \
                *_a = TAKE_STRUCT(*_b);                     \
                0;                                          \
        })

int cpu_set_realloc(CPUSet *c, size_t n);
int cpu_set_add(CPUSet *c, size_t i);
int cpu_set_add_set(CPUSet *c, const CPUSet *src);
int cpu_set_add_range(CPUSet *c, size_t start, size_t end);
int cpu_set_add_all(CPUSet *c);

char* cpu_set_to_string(const CPUSet *c);
char* cpu_set_to_range_string(const CPUSet *c);
char* cpu_set_to_mask_string(const CPUSet *c);

CONFIG_PARSER_PROTOTYPE(config_parse_cpu_set);
int parse_cpu_set(const char *s, CPUSet *ret);

int cpu_set_to_dbus(const CPUSet *c, uint8_t **ret, size_t *ret_size);
int cpu_set_from_dbus(const uint8_t *bits, size_t size, CPUSet *ret);

int cpus_in_affinity_mask(void);
