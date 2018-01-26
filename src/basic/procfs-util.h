/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>

int procfs_tasks_get_limit(uint64_t *ret);
int procfs_tasks_set_limit(uint64_t limit);
int procfs_tasks_get_current(uint64_t *ret);
