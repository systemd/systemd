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
#include "automount.h"
#include "load-fragment.h"
#include "load-dropin.h"

static const UnitActiveState state_translation_table[_AUTOMOUNT_STATE_MAX] = {
        [AUTOMOUNT_DEAD] = UNIT_INACTIVE,
        [AUTOMOUNT_WAITING] = UNIT_ACTIVE,
        [AUTOMOUNT_RUNNING] = UNIT_ACTIVE,
        [AUTOMOUNT_MAINTAINANCE] = UNIT_INACTIVE,
};

static const char* const state_string_table[_AUTOMOUNT_STATE_MAX] = {
        [AUTOMOUNT_DEAD] = "dead",
        [AUTOMOUNT_WAITING] = "waiting",
        [AUTOMOUNT_RUNNING] = "running",
        [AUTOMOUNT_MAINTAINANCE] = "maintainance"
};

static void automount_init(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        a->state = 0;
        a->mount = NULL;
}

static int automount_load(Unit *u) {
        int r;
        Automount *a = AUTOMOUNT(u);

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        /* Load a .automount file */
        if ((r = unit_load_fragment_and_dropin_optional(u)) < 0)
                return r;

        if (u->meta.load_state == UNIT_LOADED) {

                if ((r = unit_load_related_unit(u, ".mount", (Unit**) &a->mount)) < 0)
                        return r;

                if ((r = unit_add_dependency(u, UNIT_BEFORE, UNIT(a->mount))) < 0)
                        return r;
        }

        return 0;
}

static void automount_done(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);

        a->mount = NULL;
}

static void automount_dump(Unit *u, FILE *f, const char *prefix) {
        Automount *s = AUTOMOUNT(u);

        assert(s);

        fprintf(f,
                "%sAutomount State: %s\n",
                prefix, state_string_table[s->state]);
}

static UnitActiveState automount_active_state(Unit *u) {

        return state_translation_table[AUTOMOUNT(u)->state];
}

static const char *automount_sub_state_to_string(Unit *u) {
        assert(u);

        return state_string_table[AUTOMOUNT(u)->state];
}

const UnitVTable automount_vtable = {
        .suffix = ".mount",

        .no_alias = true,

        .init = automount_init,
        .load = automount_load,
        .done = automount_done,

        .dump = automount_dump,

        .active_state = automount_active_state,
        .sub_state_to_string = automount_sub_state_to_string
};
