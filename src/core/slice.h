/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "unit.h"

typedef struct Slice Slice;

struct Slice {
        Unit meta;

        SliceState state, deserialized_state;

        unsigned concurrency_soft_max;
        unsigned concurrency_hard_max;

        CGroupContext cgroup_context;

        CGroupRuntime *cgroup_runtime;
};

extern const UnitVTable slice_vtable;

DEFINE_CAST(SLICE, Slice);

unsigned slice_get_currently_active(Slice *slice, bool with_pending);

bool slice_test_concurrency_hard_max(Slice *slice);
bool slice_test_concurrency_soft_max(Slice *slice);
