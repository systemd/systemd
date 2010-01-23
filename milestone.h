/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foomilestonehfoo
#define foomilestonehfoo

typedef struct Milestone Milestone;

#include "name.h"

typedef enum MilestoneState {
        MILESTONE_DEAD,
        MILESTONE_ACTIVE
} MilestoneState;

struct Milestone {
        Meta meta;

        MilestoneState state;
};

extern const NameVTable milestone_vtable;

#endif
