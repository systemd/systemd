/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-event.h"

#include "pidref.h"

int event_reset_time(
                sd_event *e,
                sd_event_source **s,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata,
                int64_t priority,
                const char *description,
                bool force_reset);
int event_reset_time_relative(
                sd_event *e,
                sd_event_source **s,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata,
                int64_t priority,
                const char *description,
                bool force_reset);
static inline int event_source_disable(sd_event_source *s) {
        return sd_event_source_set_enabled(s, SD_EVENT_OFF);
}

int event_add_time_change(sd_event *e, sd_event_source **ret, sd_event_io_handler_t callback, void *userdata);

int event_add_child_pidref(sd_event *e, sd_event_source **s, const PidRef *pid, int options, sd_event_child_handler_t callback, void *userdata);

dual_timestamp* event_dual_timestamp_now(sd_event *e, dual_timestamp *ts);
