/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "time-util.h"

extern unsigned arg_iterations;
extern usec_t arg_base_time;

void time_parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan);
