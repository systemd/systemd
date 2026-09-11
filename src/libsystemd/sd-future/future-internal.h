/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool future_has_waiter(sd_future *f, sd_future *waiter);

/* Shared by sd_fiber_await() and cancellation cleanup: report wait errors separately from the result. */
int fiber_wait(sd_future *target, int *ret_result);
