/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>

#include "time-util.h"

int procfs_tasks_get_limit(uint64_t *ret);
int procfs_tasks_set_limit(uint64_t limit);
int procfs_tasks_get_current(uint64_t *ret);

int procfs_cpu_get_usage(nsec_t *ret);

int procfs_memory_get_current(uint64_t *ret);
