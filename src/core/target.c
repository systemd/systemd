/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dbus-target.h"
#include "dbus-unit.h"
#include "log.h"
#include "serialize.h"
#include "special.h"
#include "string-util.h"
#include "target.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_TARGET_STATE_MAX] = {
        [TARGET_DEAD] = UNIT_INACTIVE,
        [TARGET_ACTIVE] = UNIT_ACTIVE
};

static void target_set_state(Target *t, TargetState state) {
        TargetState old_state;
        assert(t);

        if (t->state != state)
                bus_unit_send_pending_change_signal(UNIT(t), false);

        old_state = t->state;
        t->state = state;

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(t)->id,
                          target_state_to_string(old_state),
                          target_state_to_string(state));

        unit_notify(UNIT(t), state_translation_table[old_state], state_translation_table[state], 0);
}

static int target_add_default_dependencies(Target *t) {
        _cleanup_free_ Unit **others = NULL;
        int r, n_others;

        assert(t);

        if (!UNIT(t)->default_dependencies)
                return 0;

        /* Imply ordering for requirement dependencies on target units. Note that when the user created a
         * contradicting ordering manually we won't add anything in here to make sure we don't create a
         * loop.
         *
         * Note that quite likely iterating through these dependencies will add new dependencies, which
         * conflicts with the hashmap-based iteration logic. Hence, instead of iterating through the
         * dependencies and acting on them as we go, first take an "atomic snapshot" of sorts and iterate
         * through that. */

        n_others = unit_get_dependency_array(UNIT(t), UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE, &others);
        if (n_others < 0)
                return n_others;

        for (int i = 0; i < n_others; i++) {
                r = unit_add_default_target_dependency(others[i], UNIT(t));
                if (r < 0)
                        return r;
        }

        if (unit_has_name(UNIT(t), SPECIAL_SHUTDOWN_TARGET))
                return 0;

        /* Make sure targets are unloaded on shutdown */
        return unit_add_two_dependencies_by_name(UNIT(t), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
}

static int target_load(Unit *u) {
        Target *t = TARGET(u);
        int r;

        assert(t);

        r = unit_load_fragment_and_dropin(u, true);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        /* This is a new unit? Then let's add in some extras */
        return target_add_default_dependencies(t);
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
        int r;

        assert(t);
        assert(t->state == TARGET_DEAD);

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        target_set_state(t, TARGET_ACTIVE);
        return 1;
}

static int target_stop(Unit *u) {
        Target *t = TARGET(u);

        assert(t);
        assert(t->state == TARGET_ACTIVE);

        target_set_state(t, TARGET_DEAD);
        return 1;
}

static int target_serialize(Unit *u, FILE *f, FDSet *fds) {
        Target *s = TARGET(u);

        assert(s);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", target_state_to_string(s->state));
        return 0;
}

static int target_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Target *s = TARGET(u);

        assert(s);
        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                TargetState state;

                state = target_state_from_string(value);
                if (state < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

_pure_ static UnitActiveState target_active_state(Unit *u) {
        assert(u);

        return state_translation_table[TARGET(u)->state];
}

_pure_ static const char *target_sub_state_to_string(Unit *u) {
        assert(u);

        return target_state_to_string(TARGET(u)->state);
}

const UnitVTable target_vtable = {
        .object_size = sizeof(Target),

        .sections =
                "Unit\0"
                "Target\0"
                "Install\0",

        .can_fail = true,

        .load = target_load,
        .coldplug = target_coldplug,

        .dump = target_dump,

        .start = target_start,
        .stop = target_stop,

        .serialize = target_serialize,
        .deserialize_item = target_deserialize_item,

        .active_state = target_active_state,
        .sub_state_to_string = target_sub_state_to_string,

        .status_message_formats = {
                .finished_start_job = {
                        [JOB_DONE]       = "Reached target %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Stopped target %s.",
                },
        },
};
