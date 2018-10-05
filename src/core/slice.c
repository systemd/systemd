/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "alloc-util.h"
#include "dbus-slice.h"
#include "log.h"
#include "slice.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_SLICE_STATE_MAX] = {
        [SLICE_DEAD] = UNIT_INACTIVE,
        [SLICE_ACTIVE] = UNIT_ACTIVE
};

static void slice_init(Unit *u) {
        assert(u);
        assert(u->load_state == UNIT_STUB);

        u->ignore_on_isolate = true;
}

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

        unit_notify(UNIT(t), state_translation_table[old_state], state_translation_table[state], 0);
}

static int slice_add_parent_slice(Slice *s) {
        Unit *u = UNIT(s), *parent;
        _cleanup_free_ char *a = NULL;
        int r;

        assert(s);

        if (UNIT_ISSET(u->slice))
                return 0;

        r = slice_build_parent_slice(u->id, &a);
        if (r <= 0) /* 0 means root slice */
                return r;

        r = manager_load_unit(u->manager, a, NULL, NULL, &parent);
        if (r < 0)
                return r;

        unit_ref_set(&u->slice, u, parent);
        return 0;
}

static int slice_add_default_dependencies(Slice *s) {
        int r;

        assert(s);

        if (!UNIT(s)->default_dependencies)
                return 0;

        /* Make sure slices are unloaded on shutdown */
        r = unit_add_two_dependencies_by_name(
                        UNIT(s),
                        UNIT_BEFORE, UNIT_CONFLICTS,
                        SPECIAL_SHUTDOWN_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
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
                return -ENOEXEC;
        }

        r = slice_build_parent_slice(UNIT(s)->id, &parent);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to determine parent slice: %m");

        if (parent ? !unit_has_name(UNIT_DEREF(UNIT(s)->slice), parent) : UNIT_ISSET(UNIT(s)->slice)) {
                log_unit_error(UNIT(s), "Located outside of parent slice. Refusing.");
                return -ENOEXEC;
        }

        return 0;
}

static int slice_load_root_slice(Unit *u) {
        assert(u);

        if (!unit_has_name(u, SPECIAL_ROOT_SLICE))
                return 0;

        u->perpetual = true;

        /* The root slice is a bit special. For example it is always running and cannot be terminated. Because of its
         * special semantics we synthesize it here, instead of relying on the unit file on disk. */

        u->default_dependencies = false;

        if (!u->description)
                u->description = strdup("Root Slice");
        if (!u->documentation)
                u->documentation = strv_new("man:systemd.special(7)", NULL);

        return 1;
}

static int slice_load_system_slice(Unit *u) {
        assert(u);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return 0;
        if (!unit_has_name(u, SPECIAL_SYSTEM_SLICE))
                return 0;

        u->perpetual = true;

        /* The system slice is a bit special. For example it is always running and cannot be terminated. Because of its
         * special semantics we synthesize it here, instead of relying on the unit file on disk. */

        u->default_dependencies = false;

        if (!u->description)
                u->description = strdup("System Slice");
        if (!u->documentation)
                u->documentation = strv_new("man:systemd.special(7)", NULL);

        return 1;
}

static int slice_load(Unit *u) {
        Slice *s = SLICE(u);
        int r;

        assert(s);
        assert(u->load_state == UNIT_STUB);

        r = slice_load_root_slice(u);
        if (r < 0)
                return r;
        r = slice_load_system_slice(u);
        if (r < 0)
                return r;

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

                r = slice_add_default_dependencies(s);
                if (r < 0)
                        return r;
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
        int r;

        assert(t);
        assert(t->state == SLICE_DEAD);

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        (void) unit_realize_cgroup(u);
        (void) unit_reset_cpu_accounting(u);
        (void) unit_reset_ip_accounting(u);

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

static int slice_make_perpetual(Manager *m, const char *name, Unit **ret) {
        Unit *u;
        int r;

        assert(m);
        assert(name);

        u = manager_get_unit(m, name);
        if (!u) {
                r = unit_new_for_name(m, sizeof(Slice), name, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate the special %s unit: %m", name);
        }

        u->perpetual = true;
        SLICE(u)->deserialized_state = SLICE_ACTIVE;

        unit_add_to_load_queue(u);
        unit_add_to_dbus_queue(u);

        if (ret)
                *ret = u;

        return 0;
}

static void slice_enumerate_perpetual(Manager *m) {
        Unit *u;
        int r;

        assert(m);

        r = slice_make_perpetual(m, SPECIAL_ROOT_SLICE, &u);
        if (r >= 0 && manager_owns_root_cgroup(m)) {
                Slice *s = SLICE(u);

                /* If we are managing the root cgroup then this means our root slice covers the whole system, which
                 * means the kernel will track CPU/tasks/memory for us anyway, and it is all available in /proc. Let's
                 * hence turn accounting on here, so that our APIs to query this data are available. */

                s->cgroup_context.cpu_accounting = true;
                s->cgroup_context.tasks_accounting = true;
                s->cgroup_context.memory_accounting = true;
        }

        if (MANAGER_IS_SYSTEM(m))
                (void) slice_make_perpetual(m, SPECIAL_SYSTEM_SLICE, NULL);
}

const UnitVTable slice_vtable = {
        .object_size = sizeof(Slice),
        .cgroup_context_offset = offsetof(Slice, cgroup_context),

        .sections =
                "Unit\0"
                "Slice\0"
                "Install\0",
        .private_section = "Slice",

        .can_transient = true,

        .init = slice_init,
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

        .bus_vtable = bus_slice_vtable,
        .bus_set_property = bus_slice_set_property,
        .bus_commit_properties = bus_slice_commit_properties,

        .enumerate_perpetual = slice_enumerate_perpetual,

        .status_message_formats = {
                .finished_start_job = {
                        [JOB_DONE]       = "Created slice %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Removed slice %s.",
                },
        },
};
