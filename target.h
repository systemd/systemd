/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef footargethfoo
#define footargethfoo

typedef struct Target Target;

#include "name.h"

typedef enum TargetState {
        TARGET_DEAD,
        TARGET_ACTIVE
} TargetState;

struct Target {
        Meta meta;

        TargetState state;
};

extern const NameVTable target_vtable;

#endif
