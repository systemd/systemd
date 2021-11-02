/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "time-util.h"

int procfs_get_pid_max(uint64_t *ret);
int procfs_get_threads_max(uint64_t *ret);

int procfs_tasks_set_limit(uint64_t limit);
int procfs_tasks_get_current(uint64_t *ret);

int procfs_cpu_get_usage(nsec_t *ret);

int procfs_memory_get(uint64_t *ret_total, uint64_t *ret_used);
static inline int procfs_memory_get_used(uint64_t *ret) {
        return procfs_memory_get(NULL, ret);
}

int convert_meminfo_value_to_uint64_bytes(const char *word, uint64_t *ret);
