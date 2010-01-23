/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "snapshot.h"

static NameActiveState snapshot_active_state(Name *n) {
        return SNAPSHOT(n)->state == SNAPSHOT_DEAD ? NAME_INACTIVE : NAME_ACTIVE;
}

static void snapshot_free_hook(Name *n) {
        Snapshot *s = SNAPSHOT(n);

        assert(s);

        /* Nothing here for now */
}

const NameVTable snapshot_vtable = {
        .suffix = ".snapshot",

        .load = NULL,
        .dump = NULL,

        .start = NULL,
        .stop = NULL,
        .reload = NULL,

        .active_state = snapshot_active_state,

        .free_hook = snapshot_free_hook
};
