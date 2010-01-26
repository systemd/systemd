/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "snapshot.h"

static void snapshot_done(Name *n) {
        Snapshot *s = SNAPSHOT(n);

        assert(s);

        /* Nothing here for now */
}

static NameActiveState snapshot_active_state(Name *n) {
        return SNAPSHOT(n)->state == SNAPSHOT_DEAD ? NAME_INACTIVE : NAME_ACTIVE;
}

const NameVTable snapshot_vtable = {
        .suffix = ".snapshot",

        .done = snapshot_done,

        .active_state = snapshot_active_state
};
