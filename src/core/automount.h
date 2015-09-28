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

typedef struct Automount Automount;

#include "unit.h"

typedef enum AutomountResult {
        AUTOMOUNT_SUCCESS,
        AUTOMOUNT_FAILURE_RESOURCES,
        _AUTOMOUNT_RESULT_MAX,
        _AUTOMOUNT_RESULT_INVALID = -1
} AutomountResult;

struct Automount {
        Unit meta;

        AutomountState state, deserialized_state;

        char *where;
        usec_t timeout_idle_usec;

        int pipe_fd;
        sd_event_source *pipe_event_source;
        mode_t directory_mode;
        dev_t dev_id;

        Set *tokens;
        Set *expire_tokens;

        sd_event_source *expire_event_source;

        AutomountResult result;
};

extern const UnitVTable automount_vtable;

int automount_update_mount(Automount *a, MountState old_state, MountState state);

const char* automount_result_to_string(AutomountResult i) _const_;
AutomountResult automount_result_from_string(const char *s) _pure_;
