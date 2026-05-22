/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool future_has_waiter(sd_future *f, sd_future *waiter);

/* Shared by sd_fiber_await() and cancellation cleanup: report wait errors separately from the result. */
int fiber_wait(sd_future *target, int *ret_result);
int event_source_inherit_fiber_priority(sd_event_source *s);

int future_new_defer(sd_event *e, int result, sd_future **ret);
