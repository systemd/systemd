/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cgroup.h"
#include "core-forward.h"
#include "unit.h"

typedef struct Slice {
        Unit meta;

        SliceState state, deserialized_state;

        unsigned concurrency_soft_max;
        unsigned concurrency_hard_max;

        CGroupContext cgroup_context;

        CGroupRuntime *cgroup_runtime;
} Slice;

extern const UnitVTable slice_vtable;

DEFINE_CAST(SLICE, Slice);

unsigned slice_get_currently_active(Slice *slice, Unit *ignore, bool with_pending);

bool slice_concurrency_hard_max_reached(Slice *slice, Unit *ignore);
bool slice_concurrency_soft_max_reached(Slice *slice, Unit *ignore);
