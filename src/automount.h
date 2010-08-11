/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooautomounthfoo
#define fooautomounthfoo

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

typedef struct Automount Automount;

#include "unit.h"

typedef enum AutomountState {
        AUTOMOUNT_DEAD,
        AUTOMOUNT_WAITING,
        AUTOMOUNT_RUNNING,
        AUTOMOUNT_MAINTENANCE,
        _AUTOMOUNT_STATE_MAX,
        _AUTOMOUNT_STATE_INVALID = -1
} AutomountState;

struct Automount {
        Meta meta;

        AutomountState state, deserialized_state;

        char *where;

        Mount *mount;

        int pipe_fd;
        mode_t directory_mode;
        Watch pipe_watch;
        dev_t dev_id;


        Set *tokens;

        bool failure:1;
};

extern const UnitVTable automount_vtable;

int automount_send_ready(Automount *a, int status);

int automount_add_one_mount_link(Automount *a, Mount *m);

const char* automount_state_to_string(AutomountState i);
AutomountState automount_state_from_string(const char *s);

#endif
