/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "unit.h"

typedef struct Slice {
        Unit meta;

        SliceState state, deserialized_state;

        CGroupContext cgroup_context;

        CGroupRuntime *cgroup_runtime;
} Slice;

extern const UnitVTable slice_vtable;

DEFINE_CAST(SLICE, Slice);
