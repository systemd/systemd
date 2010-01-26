/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "target.h"
#include "load-fragment.h"

static void target_done(Name *n) {
        Target *m = TARGET(n);

        assert(m);

        /* Nothing here for now */
}

static NameActiveState target_active_state(Name *n) {
        return TARGET(n)->state == TARGET_DEAD ? NAME_INACTIVE : NAME_ACTIVE;
}

const NameVTable target_vtable = {
        .suffix = ".target",

        .init = name_load_fragment,
        .done = target_done,

        .active_state = target_active_state
};
