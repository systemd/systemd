/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

typedef struct Slice Slice;

#include "unit.h"

typedef enum SliceState {
        SLICE_DEAD,
        SLICE_ACTIVE,
        _SLICE_STATE_MAX,
        _SLICE_STATE_INVALID = -1
} SliceState;

struct Slice {
        Unit meta;

        SliceState state, deserialized_state;

        CGroupContext cgroup_context;
};

extern const UnitVTable slice_vtable;

const char* slice_state_to_string(SliceState i) _const_;
SliceState slice_state_from_string(const char *s) _pure_;
