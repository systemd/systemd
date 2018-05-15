/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "unit.h"

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

typedef struct Target Target;

struct Target {
        Unit meta;

        TargetState state, deserialized_state;
};

extern const UnitVTable target_vtable;

DEFINE_CAST(TARGET, Target);
