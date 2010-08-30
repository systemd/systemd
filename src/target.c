/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <unistd.h>

#include "unit.h"
#include "target.h"
#include "load-fragment.h"
#include "log.h"
#include "dbus-target.h"
#include "special.h"
#include "unit-name.h"

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

static int target_add_getty_dependencies(Target *t) {
        char *n;
        int r;

        assert(t);

        if (!unit_has_name(UNIT(t), SPECIAL_GETTY_TARGET))
                return 0;

        /* Automatically add in a serial getty on the kernel
         * console */
        if (t->meta.manager->console) {
                log_debug("Automatically adding serial getty for %s", t->meta.manager->console);
                if (!(n = unit_name_replace_instance(SPECIAL_SERIAL_GETTY_SERVICE, t->meta.manager->console)))
                        return -ENOMEM;

                r = unit_add_two_dependencies_by_name(UNIT(t), UNIT_AFTER, UNIT_WANTS, n, NULL, true);
                free(n);

                if (r < 0)
                        return r;
        }

        /* Automatically add in a serial getty on the first
         * virtualizer console */
        if (access("/sys/class/tty/hvc0", F_OK) == 0) {
                log_debug("Automatic adding serial getty for hvc0");
                if (!(n = unit_name_replace_instance(SPECIAL_SERIAL_GETTY_SERVICE, "hvc0")))
                        return -ENOMEM;

                r = unit_add_two_dependencies_by_name(UNIT(t), UNIT_AFTER, UNIT_WANTS, n, NULL, true);
                free(n);

                if (r < 0)
                        return r;
        }

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

                if ((r = target_add_getty_dependencies(t)) < 0)
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

        .bus_interface = "org.freedesktop.systemd1.Target",
        .bus_message_handler = bus_target_message_handler
};
