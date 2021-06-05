/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "unit.h"

typedef struct Slice Slice;

struct Slice {
        Unit meta;

        SliceState state, deserialized_state;

        CGroupContext cgroup_context;
};

extern const UnitVTable slice_vtable;

DEFINE_CAST(SLICE, Slice);
