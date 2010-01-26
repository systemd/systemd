/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosnapshothfoo
#define foosnapshothfoo

typedef struct Snapshot Snapshot;

#include "unit.h"

typedef enum SnapshotState {
        SNAPSHOT_DEAD,
        SNAPSHOT_ACTIVE
} SnapshotState;

struct Snapshot {
        Meta meta;

        SnapshotState state;
        bool cleanup:1;
};

extern const UnitVTable snapshot_vtable;

#endif
