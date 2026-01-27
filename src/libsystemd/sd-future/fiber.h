/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

int fiber_new(sd_event *e, const char *name, FiberFunc func, void *userdata, FiberDestroy destroy, sd_future *future, Fiber **ret);
Fiber* fiber_free(Fiber *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(Fiber*, fiber_free);

int fiber_result(Fiber *f);

int fiber_set_priority(Fiber *f, int64_t priority);

int fiber_suspend(void);
int fiber_resume(sd_future *f, void *userdata);
int fiber_cancel(Fiber *f);

DISABLE_WARNING_REDUNDANT_DECLS;
Fiber* fiber_get_current(void); /* NOLINT (readability-redundant-declaration) */
void fiber_set_current(Fiber *f); /* NOLINT (readability-redundant-declaration) */
REENABLE_WARNING;
