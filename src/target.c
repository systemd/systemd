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
#include "dbus-target.h"
#include "special.h"

static const UnitActiveState state_translation_table[_TARGET_STATE_MAX] = {
        [TARGET_DEAD] = UNIT_INACTIVE,
        [TARGET_ACTIVE] = UNIT_ACTIVE
};

static void target_set_state(Target *t, TargetState state) {
        TargetState old_state;
        assert(t);

        old_state = t->state;
        t->state = state;

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          t->meta.id,
                          target_state_to_string(old_state),
                          target_state_to_string(state));

        unit_notify(UNIT(t), state_translation_table[old_state], state_translation_table[state]);
}

static int target_add_default_dependencies(Target *t) {
        Iterator i;
        Unit *other;
        int r;

        /* Imply ordering for requirement dependencies on target
         * units. Note that when the user created a contradicting
         * ordering manually we won't add anything in here to make
         * sure we don't create a loop. */

        SET_FOREACH(other, t->meta.dependencies[UNIT_REQUIRES], i)
                if (!set_get(t->meta.dependencies[UNIT_BEFORE], other))
                        if ((r = unit_add_dependency(UNIT(t), UNIT_AFTER, other, true)) < 0)
                                return r;
        SET_FOREACH(other, t->meta.dependencies[UNIT_REQUIRES_OVERRIDABLE], i)
                if (!set_get(t->meta.dependencies[UNIT_BEFORE], other))
                        if ((r = unit_add_dependency(UNIT(t), UNIT_AFTER, other, true)) < 0)
                                return r;
        SET_FOREACH(other, t->meta.dependencies[UNIT_WANTS], i)
                if (!set_get(t->meta.dependencies[UNIT_BEFORE], other))
                        if ((r = unit_add_dependency(UNIT(t), UNIT_AFTER, other, true)) < 0)
                                return r;

        return 0;
}

static int target_load(Unit *u) {
        Target *t = TARGET(u);
        int r;

        assert(t);

        if ((r = unit_load_fragment_and_dropin(u)) < 0)
                return r;

        /* This is a new unit? Then let's add in some extras */
        if (u->meta.load_state == UNIT_LOADED) {
                if (u->meta.default_dependencies)
                        if ((r = target_add_default_dependencies(t)) < 0)
                                return r;
        }

        return 0;
}

static int target_coldplug(Unit *u) {
        Target *t = TARGET(u);

        assert(t);
        assert(t->state == TARGET_DEAD);

        if (t->deserialized_state != t->state)
                target_set_state(t, t->deserialized_state);

        return 0;
}

static void target_dump(Unit *u, FILE *f, const char *prefix) {
        Target *t = TARGET(u);

        assert(t);
        assert(f);

        fprintf(f,
                "%sTarget State: %s\n",
                prefix, target_state_to_string(t->state));
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

static int target_serialize(Unit *u, FILE *f, FDSet *fds) {
        Target *s = TARGET(u);

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", target_state_to_string(s->state));
        return 0;
}

static int target_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Target *s = TARGET(u);

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                TargetState state;

                if ((state = target_state_from_string(value)) < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static UnitActiveState target_active_state(Unit *u) {
        assert(u);

        return state_translation_table[TARGET(u)->state];
}

static const char *target_sub_state_to_string(Unit *u) {
        assert(u);

        return target_state_to_string(TARGET(u)->state);
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
                { SPECIAL_RESCUE_TARGET,    '1' },
                { SPECIAL_POWEROFF_TARGET,  '0' },
                { SPECIAL_REBOOT_TARGET,    '6' },
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

static const char* const target_state_table[_TARGET_STATE_MAX] = {
        [TARGET_DEAD] = "dead",
        [TARGET_ACTIVE] = "active"
};

DEFINE_STRING_TABLE_LOOKUP(target_state, TargetState);

const UnitVTable target_vtable = {
        .suffix = ".target",

        .load = target_load,
        .coldplug = target_coldplug,

        .dump = target_dump,

        .start = target_start,
        .stop = target_stop,

        .serialize = target_serialize,
        .deserialize_item = target_deserialize_item,

        .active_state = target_active_state,
        .sub_state_to_string = target_sub_state_to_string,

        .bus_message_handler = bus_target_message_handler
};
