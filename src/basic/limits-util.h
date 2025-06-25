/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

uint64_t physical_memory(void);
uint64_t physical_memory_scale(uint64_t v, uint64_t max);

uint64_t system_tasks_max(void);
uint64_t system_tasks_max_scale(uint64_t v, uint64_t max);
