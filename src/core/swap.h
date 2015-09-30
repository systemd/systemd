/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2010 Maarten Lankhorst

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

#include <libudev.h>

typedef struct Swap Swap;

typedef enum SwapExecCommand {
        SWAP_EXEC_ACTIVATE,
        SWAP_EXEC_DEACTIVATE,
        _SWAP_EXEC_COMMAND_MAX,
        _SWAP_EXEC_COMMAND_INVALID = -1
} SwapExecCommand;

typedef enum SwapResult {
        SWAP_SUCCESS,
        SWAP_FAILURE_RESOURCES,
        SWAP_FAILURE_TIMEOUT,
        SWAP_FAILURE_EXIT_CODE,
        SWAP_FAILURE_SIGNAL,
        SWAP_FAILURE_CORE_DUMP,
        _SWAP_RESULT_MAX,
        _SWAP_RESULT_INVALID = -1
} SwapResult;

typedef struct SwapParameters {
        char *what;
        char *options;
        int priority;
} SwapParameters;

struct Swap {
        Unit meta;

        char *what;

        /* If the device has already shown up, this is the device
         * node, which might be different from what, due to
         * symlinks */
        char *devnode;

        SwapParameters parameters_proc_swaps;
        SwapParameters parameters_fragment;

        bool from_proc_swaps:1;
        bool from_fragment:1;

        /* Used while looking for swaps that vanished or got added
         * from/to /proc/swaps */
        bool is_active:1;
        bool just_activated:1;

        bool reset_cpu_usage:1;

        SwapResult result;

        usec_t timeout_usec;

        ExecCommand exec_command[_SWAP_EXEC_COMMAND_MAX];
        ExecContext exec_context;
        KillContext kill_context;
        CGroupContext cgroup_context;

        ExecRuntime *exec_runtime;

        SwapState state, deserialized_state;

        ExecCommand* control_command;
        SwapExecCommand control_command_id;
        pid_t control_pid;

        sd_event_source *timer_event_source;

        /* In order to be able to distinguish dependencies on
        different device nodes we might end up creating multiple
        devices for the same swap. We chain them up here. */

        LIST_FIELDS(struct Swap, same_devnode);
};

extern const UnitVTable swap_vtable;

int swap_process_device_new(Manager *m, struct udev_device *dev);
int swap_process_device_remove(Manager *m, struct udev_device *dev);

const char* swap_exec_command_to_string(SwapExecCommand i) _const_;
SwapExecCommand swap_exec_command_from_string(const char *s) _pure_;

const char* swap_result_to_string(SwapResult i) _const_;
SwapResult swap_result_from_string(const char *s) _pure_;
