/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "unit.h"
#include "snapshot.h"

static void snapshot_done(Unit *u) {
        Snapshot *s = SNAPSHOT(u);

        assert(s);

        /* Nothing here for now */
}

static UnitActiveState snapshot_active_state(Unit *u) {
        return SNAPSHOT(u)->state == SNAPSHOT_DEAD ? UNIT_INACTIVE : UNIT_ACTIVE;
}

const UnitVTable snapshot_vtable = {
        .suffix = ".snapshot",

        .done = snapshot_done,

        .active_state = snapshot_active_state
};
