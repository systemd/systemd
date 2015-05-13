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

typedef struct Mount Mount;

#include "kill.h"
#include "execute.h"

typedef enum MountState {
        MOUNT_DEAD,
        MOUNT_MOUNTING,               /* /usr/bin/mount is running, but the mount is not done yet. */
        MOUNT_MOUNTING_DONE,          /* /usr/bin/mount is running, and the mount is done. */
        MOUNT_MOUNTED,
        MOUNT_REMOUNTING,
        MOUNT_UNMOUNTING,
        MOUNT_MOUNTING_SIGTERM,
        MOUNT_MOUNTING_SIGKILL,
        MOUNT_REMOUNTING_SIGTERM,
        MOUNT_REMOUNTING_SIGKILL,
        MOUNT_UNMOUNTING_SIGTERM,
        MOUNT_UNMOUNTING_SIGKILL,
        MOUNT_FAILED,
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

typedef enum MountResult {
        MOUNT_SUCCESS,
        MOUNT_FAILURE_RESOURCES,
        MOUNT_FAILURE_TIMEOUT,
        MOUNT_FAILURE_EXIT_CODE,
        MOUNT_FAILURE_SIGNAL,
        MOUNT_FAILURE_CORE_DUMP,
        _MOUNT_RESULT_MAX,
        _MOUNT_RESULT_INVALID = -1
} MountResult;

typedef struct MountParameters {
        char *what;
        char *options;
        char *fstype;
} MountParameters;

struct Mount {
        Unit meta;

        char *where;

        MountParameters parameters_proc_self_mountinfo;
        MountParameters parameters_fragment;

        bool from_proc_self_mountinfo:1;
        bool from_fragment:1;

        /* Used while looking for mount points that vanished or got
         * added from/to /proc/self/mountinfo */
        bool is_mounted:1;
        bool just_mounted:1;
        bool just_changed:1;

        bool reset_cpu_usage:1;

        bool sloppy_options;

        MountResult result;
        MountResult reload_result;

        mode_t directory_mode;

        usec_t timeout_usec;

        ExecCommand exec_command[_MOUNT_EXEC_COMMAND_MAX];

        ExecContext exec_context;
        KillContext kill_context;
        CGroupContext cgroup_context;

        ExecRuntime *exec_runtime;

        MountState state, deserialized_state;

        ExecCommand* control_command;
        MountExecCommand control_command_id;
        pid_t control_pid;

        sd_event_source *timer_event_source;

        unsigned n_retry_umount;
};

extern const UnitVTable mount_vtable;

void mount_fd_event(Manager *m, int events);

const char* mount_state_to_string(MountState i) _const_;
MountState mount_state_from_string(const char *s) _pure_;

const char* mount_exec_command_to_string(MountExecCommand i) _const_;
MountExecCommand mount_exec_command_from_string(const char *s) _pure_;

const char* mount_result_to_string(MountResult i) _const_;
MountResult mount_result_from_string(const char *s) _pure_;
