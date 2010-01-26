/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "milestone.h"
#include "load-fragment.h"

static void milestone_done(Name *n) {
        Milestone *m = MILESTONE(n);

        assert(m);

        /* Nothing here for now */
}

static NameActiveState milestone_active_state(Name *n) {
        return MILESTONE(n)->state == MILESTONE_DEAD ? NAME_INACTIVE : NAME_ACTIVE;
}

const NameVTable milestone_vtable = {
        .suffix = ".milestone",

        .init = name_load_fragment,
        .done = milestone_done,

        .active_state = milestone_active_state
};
