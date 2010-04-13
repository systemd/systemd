/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <signal.h>

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

static void target_init(Unit *u) {
        Target *t = TARGET(u);

        assert(t);
        assert(u->meta.load_state == UNIT_STUB);

        t->state = 0;
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

        if (state != old_state)
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

static const char *target_sub_state_to_string(Unit *u) {
        assert(u);

        return state_string_table[TARGET(u)->state];
}

int target_get_runlevel(Target *t) {

        static const struct {
                const char *special;
                const int runlevel;
        } table[] = {
                { SPECIAL_RUNLEVEL5_TARGET, '5' },
                { SPECIAL_RUNLEVEL4_TARGET, '4' },
                { SPECIAL_RUNLEVEL3_TARGET, '3' },
                { SPECIAL_RUNLEVEL2_TARGET, '2' },
                { SPECIAL_RUNLEVEL1_TARGET, '1' },
                { SPECIAL_RUNLEVEL0_TARGET, '0' },
                { SPECIAL_RUNLEVEL6_TARGET, '6' },
        };

        unsigned i;

        assert(t);

        /* Tries to determine if this is a SysV runlevel and returns
         * it if that is so. */

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (unit_has_name(UNIT(t), table[i].special))
                        return table[i].runlevel;

        return 0;
}

const UnitVTable target_vtable = {
        .suffix = ".target",

        .init = target_init,
        .load = unit_load_fragment_and_dropin,

        .dump = target_dump,

        .start = target_start,
        .stop = target_stop,

        .active_state = target_active_state,
        .sub_state_to_string = target_sub_state_to_string
};
