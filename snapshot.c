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

#include "unit.h"
#include "snapshot.h"

static void snapshot_done(Unit *u) {
        Snapshot *s = SNAPSHOT(u);

        assert(s);

        /* Nothing here for now */
}

static UnitActiveState snapshot_active_state(Unit *u) {
        return SNAPSHOT(u)->state == SNAPSHOT_DEAD ? UNIT_INACTIVE : UNIT_ACTIVE;
}

const UnitVTable snapshot_vtable = {
        .suffix = ".snapshot",

        .done = snapshot_done,

        .active_state = snapshot_active_state
};
