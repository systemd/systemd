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

static const char* const state_string_table[_SNAPSHOT_STATE_MAX] = {
        [SNAPSHOT_DEAD] = "dead",
        [SNAPSHOT_ACTIVE] = "active"
};

static int snapshot_load(Unit *u) {
        Iterator i;
        Unit *other;
        int r;

        assert(u);

        HASHMAP_FOREACH(other, u->meta.manager->units, i) {

                if (UNIT_VTABLE(other)->no_snapshots)
                        continue;

                if ((r = unit_add_dependency(u, UNIT_REQUIRES, other)) < 0)
                        return r;

                if ((r = unit_add_dependency(u, UNIT_AFTER, other)) < 0)
                        return r;
        }

        u->meta.load_state = UNIT_LOADED;

        return 0;
}

static void snapshot_dump(Unit *u, FILE *f, const char *prefix) {
        Snapshot *s = SNAPSHOT(u);

        assert(s);
        assert(f);

        fprintf(f,
                "%sSnapshot State: %s\n"
                "%sClean Up: %s\n",
                prefix, state_string_table[s->state],
                prefix, yes_no(s->cleanup));
}

static void snapshot_set_state(Snapshot *s, SnapshotState state) {
        SnapshotState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != old_state)
                log_debug("%s changed %s → %s", UNIT(s)->meta.id, state_string_table[old_state], state_string_table[state]);

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state]);
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

static UnitActiveState snapshot_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SNAPSHOT(u)->state];
}

static const char *snapshot_sub_state_to_string(Unit *u) {
        assert(u);

        return state_string_table[SNAPSHOT(u)->state];
}

int snapshot_create(Manager *m, const char *name, bool cleanup, Snapshot **_s) {
        Unit *u;
        char *n = NULL;
        int r;

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

        r = manager_load_unit(m, name, NULL, &u);
        free(n);

        if (r < 0)
                return r;

        SNAPSHOT(u)->cleanup = cleanup;
        *_s = SNAPSHOT(u);

        return 0;
}

void snapshot_remove(Snapshot *s) {
        assert(s);

        unit_add_to_cleanup_queue(UNIT(s));
}

const UnitVTable snapshot_vtable = {
        .suffix = ".snapshot",

        .no_alias = true,
        .no_instances = true,
        .no_snapshots = true,

        .load = snapshot_load,

        .dump = snapshot_dump,

        .start = snapshot_start,
        .stop = snapshot_stop,

        .active_state = snapshot_active_state,
        .sub_state_to_string = snapshot_sub_state_to_string,

        .bus_message_handler = bus_snapshot_message_handler
};
