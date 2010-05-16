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
#include "timer.h"

static void timer_done(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
}

static UnitActiveState timer_active_state(Unit *u) {

        static const UnitActiveState table[_TIMER_STATE_MAX] = {
                [TIMER_DEAD] = UNIT_INACTIVE,
                [TIMER_WAITING] = UNIT_ACTIVE,
                [TIMER_RUNNING] = UNIT_ACTIVE
        };

        return table[TIMER(u)->state];
}

const UnitVTable timer_vtable = {
        .suffix = ".timer",

        .load = unit_load_fragment_and_dropin,
        .done = timer_done,

        .active_state = timer_active_state
};
