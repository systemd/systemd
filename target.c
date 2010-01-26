/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "unit.h"
#include "target.h"
#include "load-fragment.h"

static void target_done(Unit *u) {
        Target *m = TARGET(u);

        assert(m);

        /* Nothing here for now */
}

static UnitActiveState target_active_state(Unit *u) {
        return TARGET(u)->state == TARGET_DEAD ? UNIT_INACTIVE : UNIT_ACTIVE;
}

const UnitVTable target_vtable = {
        .suffix = ".target",

        .init = unit_load_fragment,
        .done = target_done,

        .active_state = target_active_state
};
