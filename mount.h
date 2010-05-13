/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foomounthfoo
#define foomounthfoo

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

typedef struct Mount Mount;

#include "unit.h"

typedef enum MountState {
        MOUNT_DEAD,
        MOUNT_MOUNTING,               /* /bin/mount is running, but the mount is not done yet. */
        MOUNT_MOUNTING_DONE,          /* /bin/mount is running, and the mount is done. */
        MOUNT_MOUNTED,
        MOUNT_REMOUNTING,
        MOUNT_UNMOUNTING,
        MOUNT_MOUNTING_SIGTERM,
        MOUNT_MOUNTING_SIGKILL,
        MOUNT_REMOUNTING_SIGTERM,
        MOUNT_REMOUNTING_SIGKILL,
        MOUNT_UNMOUNTING_SIGTERM,
        MOUNT_UNMOUNTING_SIGKILL,
        MOUNT_MAINTAINANCE,
        _MOUNT_STATE_MAX,
        _MOUNT_STATE_INVALID = -1
} MountState;

typedef enum MountExecCommand {
        MOUNT_EXEC_MOUNT,
        MOUNT_EXEC_UNMOUNT,
        MOUNT_EXEC_REMOUNT,
        _MOUNT_EXEC_COMMAND_MAX,
        _MOUNT_EXEC_COMMAND_INVALID = -1
} MountExecCommand;

typedef struct MountParameters {
        char *what;
        char *options;
        char *fstype;
} MountParameters;

struct Mount {
        Meta meta;

        char *where;

        MountParameters parameters_etc_fstab;
        MountParameters parameters_proc_self_mountinfo;
        MountParameters parameters_fragment;

        bool from_etc_fstab:1;
        bool from_proc_self_mountinfo:1;
        bool from_fragment:1;

        /* Used while looking for mount points that vanished or got
         * added from/to /proc/self/mountinfo */
        bool is_mounted:1;
        bool just_mounted:1;
        bool just_changed:1;

        bool failure:1;

        usec_t timeout_usec;

        ExecCommand exec_command[_MOUNT_EXEC_COMMAND_MAX];
        ExecContext exec_context;

        MountState state, deserialized_state;

        KillMode kill_mode;

        ExecCommand* control_command;
        MountExecCommand control_command_id;
        pid_t control_pid;

        Watch timer_watch;
};

extern const UnitVTable mount_vtable;

void mount_fd_event(Manager *m, int events);

int mount_path_is_mounted(Manager *m, const char* path);

const char* mount_state_to_string(MountState i);
MountState mount_state_from_string(const char *s);

const char* mount_exec_command_to_string(MountExecCommand i);
MountExecCommand mount_exec_command_from_string(const char *s);

#endif
