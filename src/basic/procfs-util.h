/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "alloc-util.h"
#include "string-util.h"
#include "time-util.h"

#define procfs_file_alloca(pid, field)                                  \
        ({                                                              \
                pid_t _pid_ = (pid);                                    \
                const char *_field_ = (field);                          \
                char *_r_;                                              \
                if (_pid_ == 0)                                         \
                        _r_ = strjoina("/proc/self/", _field_);         \
                else {                                                  \
                        assert(_pid_ > 0);                              \
                        _r_ = newa(char, STRLEN("/proc/") + DECIMAL_STR_MAX(pid_t) + 1 + strlen(_field_) + 1); \
                        sprintf(_r_, "/proc/" PID_FMT "/%s", _pid_, _field_); \
                }                                                       \
                (const char*) _r_;                                      \
        })

int procfs_file_get_field(pid_t pid, const char *name, const char *key, char **ret);

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
