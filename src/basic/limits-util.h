/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>

uint64_t physical_memory(void);
uint64_t physical_memory_scale(uint64_t v, uint64_t max);

uint64_t system_tasks_max(void);
uint64_t system_tasks_max_scale(uint64_t v, uint64_t max);
