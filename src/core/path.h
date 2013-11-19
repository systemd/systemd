/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
        PATH_EXISTS_GLOB,
        PATH_DIRECTORY_NOT_EMPTY,
        PATH_CHANGED,
        PATH_MODIFIED,
        _PATH_TYPE_MAX,
        _PATH_TYPE_INVALID = -1
} PathType;

typedef struct PathSpec {
        Unit *unit;

        char *path;

        sd_event_source *event_source;

        LIST_FIELDS(struct PathSpec, spec);

        PathType type;
        int inotify_fd;
        int primary_wd;

        bool previous_exists;
} PathSpec;

int path_spec_watch(PathSpec *s, sd_event_io_handler_t handler);
void path_spec_unwatch(PathSpec *s);
int path_spec_fd_event(PathSpec *s, uint32_t events);
void path_spec_done(PathSpec *s);

static inline bool path_spec_owns_inotify_fd(PathSpec *s, int fd) {
        return s->inotify_fd == fd;
}

typedef enum PathResult {
        PATH_SUCCESS,
        PATH_FAILURE_RESOURCES,
        _PATH_RESULT_MAX,
        _PATH_RESULT_INVALID = -1
} PathResult;

struct Path {
        Unit meta;

        LIST_HEAD(PathSpec, specs);

        PathState state, deserialized_state;

        bool inotify_triggered;

        bool make_directory;
        mode_t directory_mode;

        PathResult result;
};

void path_free_specs(Path *p);

extern const UnitVTable path_vtable;

const char* path_state_to_string(PathState i) _const_;
PathState path_state_from_string(const char *s) _pure_;

const char* path_type_to_string(PathType i) _const_;
PathType path_type_from_string(const char *s) _pure_;

const char* path_result_to_string(PathResult i) _const_;
PathResult path_result_from_string(const char *s) _pure_;
