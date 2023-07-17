/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "unit.h"

typedef struct Slice Slice;

struct Slice {
        Unit meta;

        SliceState state, deserialized_state;

        CGroupContext cgroup_context;

        unsigned n_units;   /* The number of units running under this slice */
        unsigned n_max_units;   /* The max. number of units allowed to run under this slice */
};

extern const UnitVTable slice_vtable;

DEFINE_CAST(SLICE, Slice);
