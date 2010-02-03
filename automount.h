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
        AUTOMOUNT_START_PRE,
        AUTOMOUNT_START_POST,
        AUTOMOUNT_WAITING,
        AUTOMOUNT_RUNNING,
        AUTOMOUNT_STOP_PRE,
        AUTOMOUNT_STOP_POST,
        AUTOMOUNT_MAINTAINANCE,
        _AUTOMOUNT_STATE_MAX
} AutomountState;

typedef enum AutomountExecCommand {
        AUTOMOUNT_EXEC_START_PRE,
        AUTOMOUNT_EXEC_START_POST,
        AUTOMOUNT_EXEC_STOP_PRE,
        AUTOMOUNT_EXEC_STOP_POST,
        _AUTOMOUNT_EXEC_MAX
} AutomountExecCommand;

struct Automount {
        Meta meta;

        AutomountState state;
        char *path;

        ExecCommand* exec_command[_AUTOMOUNT_EXEC_MAX];
        ExecContext exec_context;

        pid_t contol_pid;

        Mount *mount;
};

extern const UnitVTable automount_vtable;

#endif
