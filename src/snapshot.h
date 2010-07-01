/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosnapshothfoo
#define foosnapshothfoo

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

typedef struct Snapshot Snapshot;

#include "unit.h"

typedef enum SnapshotState {
        SNAPSHOT_DEAD,
        SNAPSHOT_ACTIVE,
        _SNAPSHOT_STATE_MAX,
        _SNAPSHOT_STATE_INVALID = -1
} SnapshotState;

struct Snapshot {
        Meta meta;

        SnapshotState state, deserialized_state;

        bool cleanup;
        bool by_snapshot_create:1;
};

extern const UnitVTable snapshot_vtable;

int snapshot_create(Manager *m, const char *name, bool cleanup, Snapshot **s);
void snapshot_remove(Snapshot *s);

const char* snapshot_state_to_string(SnapshotState i);
SnapshotState snapshot_state_from_string(const char *s);

#endif
