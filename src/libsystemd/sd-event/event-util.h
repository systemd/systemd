/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "forward.h"

extern const struct hash_ops event_source_hash_ops;

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

int event_add_child_pidref(sd_event *e, sd_event_source **ret, const PidRef *pid, int options, sd_event_child_handler_t callback, void *userdata);

int event_source_get_child_pidref(sd_event_source *s, PidRef *ret);

dual_timestamp* event_dual_timestamp_now(sd_event *e, dual_timestamp *ts);

void event_source_unref_many(sd_event_source **array, size_t n);

int event_forward_signals(sd_event *e, sd_event_source *child, const int *signals, size_t n_signals, sd_event_source ***ret_sources, size_t *ret_n_sources);
