/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef footargethfoo
#define footargethfoo

typedef struct Target Target;

#include "unit.h"

typedef enum TargetState {
        TARGET_DEAD,
        TARGET_ACTIVE
} TargetState;

struct Target {
        Meta meta;

        TargetState state;
};

extern const UnitVTable target_vtable;

#endif
