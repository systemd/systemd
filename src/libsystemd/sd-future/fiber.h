/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "sd-forward.h"

#include "fiber-def.h"          /* IWYU pragma: export */

int fiber_new(sd_event *e, const char *name, FiberFunc func, void *userdata, FiberDestroy destroy, sd_future *future, Fiber **ret);
Fiber* fiber_free(Fiber *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(Fiber*, fiber_free);

int fiber_result(Fiber *f);

int fiber_set_priority(Fiber *f, int64_t priority);

int fiber_cancel(Fiber *f);
