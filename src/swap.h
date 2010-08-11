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
        SWAP_MAINTENANCE,
        _SWAP_STATE_MAX,
        _SWAP_STATE_INVALID = -1
} SwapState;

typedef struct SwapParameters {
        char *what;
        int priority;
        bool noauto:1;
        bool handle:1;
} SwapParameters;

struct Swap {
        Meta meta;

        SwapParameters parameters_etc_fstab;
        SwapParameters parameters_proc_swaps;
        SwapParameters parameters_fragment;

        char *what;

        SwapState state, deserialized_state;

        bool from_etc_fstab:1;
        bool from_proc_swaps:1;
        bool from_fragment:1;
};

extern const UnitVTable swap_vtable;

int swap_add_one(Manager *m, const char *what, int prio, bool no_auto, bool handle, bool from_proc_swap);

int swap_add_one_mount_link(Swap *s, Mount *m);

const char* swap_state_to_string(SwapState i);
SwapState swap_state_from_string(const char *s);


#endif
