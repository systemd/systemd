/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooswaphfoo
#define fooswaphfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2010 Maarten Lankhorst

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

typedef struct Swap Swap;

#include "unit.h"

typedef enum SwapState {
        SWAP_DEAD,
        SWAP_ACTIVE,
        SWAP_MAINTAINANCE,
        _SWAP_STATE_MAX,
        _SWAP_STATE_INVALID = -1
} SwapState;

struct Swap {
        Meta meta;

        char *what;

        int priority;

        bool no_auto;

        bool from_proc_swaps_only:1;
        bool found_in_proc_swaps:1;

        MountState state, deserialized_state;
};

extern const UnitVTable swap_vtable;

const char* swap_state_to_string(SwapState i);
SwapState swap_state_from_string(const char *s);

extern int swap_add_one(Manager *m, const char *what, bool no_auto, int prio, bool from_proc_swap);

#endif
