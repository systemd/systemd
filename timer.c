/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "unit.h"
#include "timer.h"

static void timer_done(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
}

static int timer_init(Unit *u) {
        int r;

        assert(u);

        /* Make sure this config file actually exists */

        if ((r = unit_load_fragment_and_dropin(u)) <= 0)
                return r < 0 ? r : -ENOENT;

        return 0;
}

static UnitActiveState timer_active_state(Unit *u) {

        static const UnitActiveState table[_TIMER_STATE_MAX] = {
                [TIMER_DEAD] = UNIT_INACTIVE,
                [TIMER_WAITING] = UNIT_ACTIVE,
                [TIMER_RUNNING] = UNIT_ACTIVE
        };

        return table[TIMER(u)->state];
}

const UnitVTable timer_vtable = {
        .suffix = ".timer",

        .init = timer_init,
        .done = timer_done,

        .active_state = timer_active_state
};
