/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "milestone.h"
#include "load-fragment.h"

static NameActiveState milestone_active_state(Name *n) {
        return MILESTONE(n)->state == MILESTONE_DEAD ? NAME_INACTIVE : NAME_ACTIVE;
}

static void milestone_free_hook(Name *n) {
        Milestone *m = MILESTONE(n);

        assert(m);

        /* Nothing here for now */
}

const NameVTable milestone_vtable = {
        .suffix = ".milestone",

        .load = name_load_fragment,
        .dump = NULL,

        .start = NULL,
        .stop = NULL,
        .reload = NULL,

        .active_state = milestone_active_state,

        .free_hook = milestone_free_hook
};
