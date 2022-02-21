/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "bus-util.h"
#include "pager.h"
#include "time-util.h"

extern PagerFlags arg_pager_flags;
extern BusTransport arg_transport;
extern unsigned arg_iterations;
extern usec_t arg_base_time;
extern bool arg_quiet;

int acquire_bus(sd_bus **bus, bool *use_full_bus);

void time_parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan);
