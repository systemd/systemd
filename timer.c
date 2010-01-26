/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "timer.h"

static void timer_done(Name *n) {
        Timer *t = TIMER(n);

        assert(t);
}

static NameActiveState timer_active_state(Name *n) {

        static const NameActiveState table[_TIMER_STATE_MAX] = {
                [TIMER_DEAD] = NAME_INACTIVE,
                [TIMER_WAITING] = NAME_ACTIVE,
                [TIMER_RUNNING] = NAME_ACTIVE
        };

        return table[TIMER(n)->state];
}

const NameVTable timer_vtable = {
        .suffix = ".timer",

        .init = name_load_fragment_and_dropin,
        .done = timer_done,

        .active_state = timer_active_state
};
