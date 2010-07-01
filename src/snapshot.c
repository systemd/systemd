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

#include "unit.h"
#include "snapshot.h"
#include "unit-name.h"
#include "dbus-snapshot.h"

static const UnitActiveState state_translation_table[_SNAPSHOT_STATE_MAX] = {
        [SNAPSHOT_DEAD] = UNIT_INACTIVE,
        [SNAPSHOT_ACTIVE] = UNIT_ACTIVE
};

static void snapshot_set_state(Snapshot *s, SnapshotState state) {
        SnapshotState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          s->meta.id,
                          snapshot_state_to_string(old_state),
                          snapshot_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state]);
}

static int snapshot_load(Unit *u) {
        Snapshot *s = SNAPSHOT(u);

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        /* Make sure that only snapshots created via snapshot_create()
         * can be loaded */
        if (!s->by_snapshot_create)
                return -ENOENT;

        u->meta.load_state = UNIT_LOADED;
        return 0;
}

static int snapshot_coldplug(Unit *u) {
        Snapshot *s = SNAPSHOT(u);

        assert(s);
        assert(s->state == SNAPSHOT_DEAD);

        if (s->deserialized_state != s->state)
                snapshot_set_state(s, s->deserialized_state);

        return 0;
}

static void snapshot_dump(Unit *u, FILE *f, const char *prefix) {
        Snapshot *s = SNAPSHOT(u);

        assert(s);
        assert(f);

        fprintf(f,
                "%sSnapshot State: %s\n"
                "%sClean Up: %s\n",
                prefix, snapshot_state_to_string(s->state),
                prefix, yes_no(s->cleanup));
}

static int snapshot_start(Unit *u) {
        Snapshot *s = SNAPSHOT(u);

        assert(s);
        assert(s->state == SNAPSHOT_DEAD);

        snapshot_set_state(s, SNAPSHOT_ACTIVE);

        if (s->cleanup)
                unit_add_to_cleanup_queue(u);

        return 0;
}

static int snapshot_stop(Unit *u) {
        Snapshot *s = SNAPSHOT(u);

        assert(s);
        assert(s->state == SNAPSHOT_ACTIVE);

        snapshot_set_state(s, SNAPSHOT_DEAD);
        return 0;
}

static int snapshot_serialize(Unit *u, FILE *f, FDSet *fds) {
        Snapshot *s = SNAPSHOT(u);
        Unit *other;
        Iterator i;

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", snapshot_state_to_string(s->state));
        unit_serialize_item(u, f, "cleanup", yes_no(s->cleanup));
        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUIRES], i)
                unit_serialize_item(u, f, "requires", other->meta.id);

        return 0;
}

static int snapshot_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Snapshot *s = SNAPSHOT(u);
        int r;

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                SnapshotState state;

                if ((state = snapshot_state_from_string(value)) < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;

        } else if (streq(key, "cleanup")) {

                if ((r = parse_boolean(value)) < 0)
                        log_debug("Failed to parse cleanup value %s", value);
                else
                        s->cleanup = r;

        } else if (streq(key, "requires")) {

                if ((r = unit_add_dependency_by_name(u, UNIT_AFTER, value, NULL, true)) < 0)
                        return r;

                if ((r = unit_add_dependency_by_name(u, UNIT_REQUIRES, value, NULL, true)) < 0)
                        return r;
        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static UnitActiveState snapshot_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SNAPSHOT(u)->state];
}

static const char *snapshot_sub_state_to_string(Unit *u) {
        assert(u);

        return snapshot_state_to_string(SNAPSHOT(u)->state);
}

int snapshot_create(Manager *m, const char *name, bool cleanup, Snapshot **_s) {
        Iterator i;
        Unit *other, *u = NULL;
        char *n = NULL;
        int r;
        const char *k;

        assert(m);
        assert(_s);

        if (name) {
                if (!unit_name_is_valid(name))
                        return -EINVAL;

                if (unit_name_to_type(name) != UNIT_SNAPSHOT)
                        return -EINVAL;

                if (manager_get_unit(m, name))
                        return -EEXIST;

        } else {

                for (;;) {
                        if (asprintf(&n, "snapshot-%u.snapshot", ++ m->n_snapshots) < 0)
                                return -ENOMEM;

                        if (!manager_get_unit(m, n))
                                break;

                        free(n);
                }

                name = n;
        }

        r = manager_load_unit_prepare(m, name, NULL, &u);
        free(n);

        if (r < 0)
                goto fail;

        SNAPSHOT(u)->by_snapshot_create = true;
        manager_dispatch_load_queue(m);
        assert(u->meta.load_state == UNIT_LOADED);

        HASHMAP_FOREACH_KEY(other, k, m->units, i) {

                if (UNIT_VTABLE(other)->no_snapshots)
                        continue;

                if (k != other->meta.id)
                        continue;

                if (UNIT_VTABLE(other)->check_snapshot)
                        if (!UNIT_VTABLE(other)->check_snapshot(other))
                            continue;

                if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        continue;

                if ((r = unit_add_dependency(u, UNIT_REQUIRES, other, true)) < 0)
                        goto fail;

                if ((r = unit_add_dependency(u, UNIT_AFTER, other, true)) < 0)
                        goto fail;
        }

        SNAPSHOT(u)->cleanup = cleanup;
        *_s = SNAPSHOT(u);

        return 0;

fail:
        if (u)
                unit_add_to_cleanup_queue(u);

        return r;
}

void snapshot_remove(Snapshot *s) {
        assert(s);

        unit_add_to_cleanup_queue(UNIT(s));
}

static const char* const snapshot_state_table[_SNAPSHOT_STATE_MAX] = {
        [SNAPSHOT_DEAD] = "dead",
        [SNAPSHOT_ACTIVE] = "active"
};

DEFINE_STRING_TABLE_LOOKUP(snapshot_state, SnapshotState);

const UnitVTable snapshot_vtable = {
        .suffix = ".snapshot",

        .no_alias = true,
        .no_instances = true,
        .no_snapshots = true,
        .no_gc = true,

        .load = snapshot_load,
        .coldplug = snapshot_coldplug,

        .dump = snapshot_dump,

        .start = snapshot_start,
        .stop = snapshot_stop,

        .serialize = snapshot_serialize,
        .deserialize_item = snapshot_deserialize_item,

        .active_state = snapshot_active_state,
        .sub_state_to_string = snapshot_sub_state_to_string,

        .bus_message_handler = bus_snapshot_message_handler
};
