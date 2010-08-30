/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef footimerhfoo
#define footimerhfoo

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

typedef struct Timer Timer;

#include "unit.h"

typedef enum TimerState {
        TIMER_DEAD,
        TIMER_WAITING,
        TIMER_RUNNING,
        TIMER_ELAPSED,
        TIMER_FAILED,
        _TIMER_STATE_MAX,
        _TIMER_STATE_INVALID = -1
} TimerState;

typedef enum TimerBase {
        TIMER_ACTIVE,
        TIMER_BOOT,
        TIMER_STARTUP,
        TIMER_UNIT_ACTIVE,
        TIMER_UNIT_INACTIVE,
        _TIMER_BASE_MAX,
        _TIMER_BASE_INVALID = -1
} TimerBase;

typedef struct TimerValue {
        usec_t value;
        usec_t next_elapse;

        LIST_FIELDS(struct TimerValue, value);

        TimerBase base;
        bool disabled;
} TimerValue;

struct Timer {
        Meta meta;

        LIST_HEAD(TimerValue, values);
        usec_t next_elapse;

        TimerState state, deserialized_state;
        Unit *unit;

        Watch timer_watch;

        bool failure;
};

void timer_unit_notify(Unit *u, UnitActiveState new_state);

extern const UnitVTable timer_vtable;

const char *timer_state_to_string(TimerState i);
TimerState timer_state_from_string(const char *s);

const char *timer_base_to_string(TimerBase i);
TimerBase timer_base_from_string(const char *s);

#endif
