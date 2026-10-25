/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "forward.h"

/* A refcounted handle for one raw io_uring submission. Internal only: handing out a live struct
 * io_uring_sqe carries contracts (don't touch it once we submit, don't reclaim buffers until the terminal
 * CQE) that we can't support as a stable API across kernels and opcodes. */
typedef struct sd_event_slot sd_event_slot;
typedef int (*sd_event_io_uring_handler_t)(sd_event_slot *s, int32_t res, uint32_t flags, void *userdata);

bool event_io_uring_available(sd_event *e);
int event_add_io_uring_sqe(sd_event *e, sd_event_slot **ret_slot, struct io_uring_sqe **ret_sqe, sd_event_io_uring_handler_t callback, void *userdata);
sd_event_slot* event_slot_ref(sd_event_slot *p);
sd_event_slot* event_slot_unref(sd_event_slot *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_event_slot*, event_slot_unref);
int event_slot_cancel(sd_event_slot *s);
int event_slot_set_priority(sd_event_slot *s, int64_t priority);
