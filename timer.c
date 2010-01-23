/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "timer.h"

static NameActiveState timer_active_state(Name *n) {

        static const NameActiveState table[_TIMER_STATE_MAX] = {
                [TIMER_DEAD] = NAME_INACTIVE,
                [TIMER_WAITING] = NAME_ACTIVE,
                [TIMER_RUNNING] = NAME_ACTIVE
        };

        return table[TIMER(n)->state];
}

static void timer_free_hook(Name *n) {
        Timer *t = TIMER(n);

        assert(t);

        if (t->service)
                t->service->timer = NULL;
}

const NameVTable timer_vtable = {
        .suffix = ".timer",

        .load = name_load_fragment_and_dropin,
        .dump = NULL,

        .start = NULL,
        .stop = NULL,
        .reload = NULL,

        .active_state = timer_active_state,

        .free_hook = timer_free_hook
};
