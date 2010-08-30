/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foopathhfoo
#define foopathhfoo

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

typedef struct Path Path;

#include "unit.h"
#include "mount.h"

typedef enum PathState {
        PATH_DEAD,
        PATH_WAITING,
        PATH_RUNNING,
        PATH_FAILED,
        _PATH_STATE_MAX,
        _PATH_STATE_INVALID = -1
} PathState;

typedef enum PathType {
        PATH_EXISTS,
        PATH_DIRECTORY_NOT_EMPTY,
        PATH_CHANGED,
        _PATH_TYPE_MAX,
        _PATH_TYPE_INVALID = -1
} PathType;

typedef struct PathSpec {
        char *path;

        Watch watch;

        LIST_FIELDS(struct PathSpec, spec);

        PathType type;
        int inotify_fd;
        int primary_wd;

        bool previous_exists;

} PathSpec;

struct Path {
        Meta meta;

        LIST_HEAD(PathSpec, specs);

        Unit *unit;

        PathState state, deserialized_state;

        bool failure;
};

void path_unit_notify(Unit *u, UnitActiveState new_state);

/* Called from the mount code figure out if a mount is a dependency of
 * any of the paths of this path object */
int path_add_one_mount_link(Path *p, Mount *m);

extern const UnitVTable path_vtable;

const char* path_state_to_string(PathState i);
PathState path_state_from_string(const char *s);

const char* path_type_to_string(PathType i);
PathType path_type_from_string(const char *s);

#endif
