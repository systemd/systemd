/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "unit.h"
#include "target.h"
#include "load-fragment.h"
#include "log.h"

static const UnitActiveState state_translation_table[_TARGET_STATE_MAX] = {
        [TARGET_DEAD] = UNIT_INACTIVE,
        [TARGET_ACTIVE] = UNIT_ACTIVE
};

static const char* const state_string_table[_TARGET_STATE_MAX] = {
        [TARGET_DEAD] = "dead",
        [TARGET_ACTIVE] = "active"
};

static int target_init(Unit *u) {
        int r;
        assert(u);

        /* Make sure this config file actually exists */

        if ((r = unit_load_fragment_and_dropin(u)) <= 0)
                return r < 0 ? r : -ENOENT;

        return 0;
}

static void target_dump(Unit *u, FILE *f, const char *prefix) {
        Target *t = TARGET(u);

        assert(t);
        assert(f);

        fprintf(f,
                "%sTarget State: %s\n",
                prefix, state_string_table[t->state]);
}

static void target_set_state(Target *t, TargetState state) {
        TargetState old_state;
        assert(t);

        old_state = t->state;
        t->state = state;

        log_debug("%s changed %s → %s", unit_id(UNIT(t)), state_string_table[old_state], state_string_table[state]);

        unit_notify(UNIT(t), state_translation_table[old_state], state_translation_table[state]);
}

static int target_start(Unit *u) {
        Target *t = TARGET(u);

        assert(t);
        assert(t->state == TARGET_DEAD);

        target_set_state(t, TARGET_ACTIVE);
        return 0;
}

static int target_stop(Unit *u) {
        Target *t = TARGET(u);

        assert(t);
        assert(t->state == TARGET_ACTIVE);

        target_set_state(t, TARGET_DEAD);
        return 0;
}

static UnitActiveState target_active_state(Unit *u) {
        assert(u);

        return state_translation_table[TARGET(u)->state];
}

const UnitVTable target_vtable = {
        .suffix = ".target",

        .init = target_init,

        .dump = target_dump,

        .start = target_start,
        .stop = target_stop,

        .active_state = target_active_state
};
