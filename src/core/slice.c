/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>

#include "unit.h"
#include "slice.h"
#include "log.h"
#include "dbus-slice.h"
#include "special.h"
#include "unit-name.h"

static const UnitActiveState state_translation_table[_SLICE_STATE_MAX] = {
        [SLICE_DEAD] = UNIT_INACTIVE,
        [SLICE_ACTIVE] = UNIT_ACTIVE
};

static void slice_set_state(Slice *t, SliceState state) {
        SliceState old_state;
        assert(t);

        old_state = t->state;
        t->state = state;

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(t)->id,
                          slice_state_to_string(old_state),
                          slice_state_to_string(state));

        unit_notify(UNIT(t), state_translation_table[old_state], state_translation_table[state], true);
}

static int slice_add_parent_slice(Slice *s) {
        char *a, *dash;
        Unit *parent;
        int r;

        assert(s);

        if (UNIT_ISSET(UNIT(s)->slice))
                return 0;

        if (unit_has_name(UNIT(s), SPECIAL_ROOT_SLICE))
                return 0;

        a = strdupa(UNIT(s)->id);
        dash = strrchr(a, '-');
        if (dash)
                strcpy(dash, ".slice");
        else
                a = (char*) SPECIAL_ROOT_SLICE;

        r = manager_load_unit(UNIT(s)->manager, a, NULL, NULL, &parent);
        if (r < 0)
                return r;

        unit_ref_set(&UNIT(s)->slice, parent);
        return 0;
}

static int slice_add_default_dependencies(Slice *s) {
        int r;

        assert(s);

        /* Make sure slices are unloaded on shutdown */
        r = unit_add_two_dependencies_by_name(
                        UNIT(s),
                        UNIT_BEFORE, UNIT_CONFLICTS,
                        SPECIAL_SHUTDOWN_TARGET, NULL, true);
        if (r < 0)
                return r;

        return 0;
}


static int slice_verify(Slice *s) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(s);

        if (UNIT(s)->load_state != UNIT_LOADED)
                return 0;

        if (!slice_name_is_valid(UNIT(s)->id)) {
                log_unit_error(UNIT(s), "Slice name %s is not valid. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        r = slice_build_parent_slice(UNIT(s)->id, &parent);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to determine parent slice: %m");

        if (parent ? !unit_has_name(UNIT_DEREF(UNIT(s)->slice), parent) : UNIT_ISSET(UNIT(s)->slice)) {
                log_unit_error(UNIT(s), "Located outside of parent slice. Refusing.");
                return -EINVAL;
        }

        return 0;
}

static int slice_load(Unit *u) {
        Slice *s = SLICE(u);
        int r;

        assert(s);

        r = unit_load_fragment_and_dropin_optional(u);
        if (r < 0)
                return r;

        /* This is a new unit? Then let's add in some extras */
        if (u->load_state == UNIT_LOADED) {

                r = unit_patch_contexts(u);
                if (r < 0)
                        return r;

                r = slice_add_parent_slice(s);
                if (r < 0)
                        return r;

                if (u->default_dependencies) {
                        r = slice_add_default_dependencies(s);
                        if (r < 0)
                                return r;
                }
        }

        return slice_verify(s);
}

static int slice_coldplug(Unit *u) {
        Slice *t = SLICE(u);

        assert(t);
        assert(t->state == SLICE_DEAD);

        if (t->deserialized_state != t->state)
                slice_set_state(t, t->deserialized_state);

        return 0;
}

static void slice_dump(Unit *u, FILE *f, const char *prefix) {
        Slice *t = SLICE(u);

        assert(t);
        assert(f);

        fprintf(f,
                "%sSlice State: %s\n",
                prefix, slice_state_to_string(t->state));

        cgroup_context_dump(&t->cgroup_context, f, prefix);
}

static int slice_start(Unit *u) {
        Slice *t = SLICE(u);

        assert(t);
        assert(t->state == SLICE_DEAD);

        (void) unit_realize_cgroup(u);
        (void) unit_reset_cpu_usage(u);

        slice_set_state(t, SLICE_ACTIVE);
        return 1;
}

static int slice_stop(Unit *u) {
        Slice *t = SLICE(u);

        assert(t);
        assert(t->state == SLICE_ACTIVE);

        /* We do not need to destroy the cgroup explicitly,
         * unit_notify() will do that for us anyway. */

        slice_set_state(t, SLICE_DEAD);
        return 1;
}

static int slice_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        return unit_kill_common(u, who, signo, -1, -1, error);
}

static int slice_serialize(Unit *u, FILE *f, FDSet *fds) {
        Slice *s = SLICE(u);

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", slice_state_to_string(s->state));
        return 0;
}

static int slice_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Slice *s = SLICE(u);

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                SliceState state;

                state = slice_state_from_string(value);
                if (state < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

_pure_ static UnitActiveState slice_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SLICE(u)->state];
}

_pure_ static const char *slice_sub_state_to_string(Unit *u) {
        assert(u);

        return slice_state_to_string(SLICE(u)->state);
}

static const char* const slice_state_table[_SLICE_STATE_MAX] = {
        [SLICE_DEAD] = "dead",
        [SLICE_ACTIVE] = "active"
};

DEFINE_STRING_TABLE_LOOKUP(slice_state, SliceState);

const UnitVTable slice_vtable = {
        .object_size = sizeof(Slice),
        .cgroup_context_offset = offsetof(Slice, cgroup_context),

        .sections =
                "Unit\0"
                "Slice\0"
                "Install\0",
        .private_section = "Slice",

        .no_alias = true,
        .no_instances = true,

        .load = slice_load,

        .coldplug = slice_coldplug,

        .dump = slice_dump,

        .start = slice_start,
        .stop = slice_stop,

        .kill = slice_kill,

        .serialize = slice_serialize,
        .deserialize_item = slice_deserialize_item,

        .active_state = slice_active_state,
        .sub_state_to_string = slice_sub_state_to_string,

        .bus_interface = "org.freedesktop.systemd1.Slice",
        .bus_vtable = bus_slice_vtable,
        .bus_set_property = bus_slice_set_property,
        .bus_commit_properties = bus_slice_commit_properties,

        .status_message_formats = {
                .finished_start_job = {
                        [JOB_DONE]       = "Created slice %s.",
                        [JOB_DEPENDENCY] = "Dependency failed for %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Removed slice %s.",
                },
        },
};
