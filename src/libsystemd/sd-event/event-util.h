/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "sd-event.h"

int event_reset_time(sd_event *e, sd_event_source **s,
                     clockid_t clock, uint64_t usec, uint64_t accuracy,
                     sd_event_time_handler_t callback, void *userdata,
                     int64_t priority, const char *description, bool force_reset);
