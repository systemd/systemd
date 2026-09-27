/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "forward.h"

#define PROTECT_EVENT(e)                                                \
        _unused_ _cleanup_(sd_event_unrefp) sd_event *_ref = sd_event_ref(e);

extern const struct hash_ops event_source_hash_ops;

sd_event* event_resolve(sd_event *e);

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

/* A refcounted handle for one raw io_uring submission. Internal only: handing out a live struct
 * io_uring_sqe carries contracts (don't touch it once we submit, don't reclaim buffers until the terminal
 * CQE) that we can't support as a stable API across kernels and opcodes. */
typedef struct sd_event_slot sd_event_slot;
struct io_uring_sqe;
typedef int (*sd_event_io_uring_handler_t)(sd_event_slot *s, int32_t res, uint32_t flags, void *userdata);

int event_add_io_uring_sqe(sd_event *e, sd_event_slot **ret_slot, struct io_uring_sqe **ret_sqe, sd_event_io_uring_handler_t callback, void *userdata);
sd_event_slot* event_slot_ref(sd_event_slot *s);
sd_event_slot* event_slot_unref(sd_event_slot *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_event_slot*, event_slot_unref);
int event_slot_cancel(sd_event_slot *s);
int event_slot_set_priority(sd_event_slot *s, int64_t priority);
sd_event* event_slot_get_event(sd_event_slot *s);
