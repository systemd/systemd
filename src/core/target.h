/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"
#include "unit.h"

typedef struct Target {
        Unit meta;

        TargetState state, deserialized_state;
} Target;

extern const UnitVTable target_vtable;

DEFINE_CAST(TARGET, Target);
