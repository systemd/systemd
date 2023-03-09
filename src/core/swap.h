/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2010 Maarten Lankhorst
***/

#include "sd-device.h"
#include "unit.h"

typedef struct Swap Swap;

typedef enum SwapExecCommand {
        SWAP_EXEC_ACTIVATE,
        SWAP_EXEC_DEACTIVATE,
        _SWAP_EXEC_COMMAND_MAX,
        _SWAP_EXEC_COMMAND_INVALID = -EINVAL,
} SwapExecCommand;

typedef enum SwapResult {
        SWAP_SUCCESS,
        SWAP_FAILURE_RESOURCES,
        SWAP_FAILURE_TIMEOUT,
        SWAP_FAILURE_EXIT_CODE,
        SWAP_FAILURE_SIGNAL,
        SWAP_FAILURE_CORE_DUMP,
        SWAP_FAILURE_START_LIMIT_HIT,
        _SWAP_RESULT_MAX,
        _SWAP_RESULT_INVALID = -EINVAL,
} SwapResult;

typedef struct SwapParameters {
        char *what;
        char *options;
        int priority;
        bool priority_set;
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

        SwapResult result;
        SwapResult clean_result;

        usec_t timeout_usec;

        ExecCommand exec_command[_SWAP_EXEC_COMMAND_MAX];
        ExecContext exec_context;
        KillContext kill_context;
        CGroupContext cgroup_context;

        ExecRuntime *exec_runtime;
        DynamicCreds dynamic_creds;

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

int swap_process_device_new(Manager *m, sd_device *dev);
int swap_process_device_remove(Manager *m, sd_device *dev);

const char* swap_exec_command_to_string(SwapExecCommand i) _const_;
SwapExecCommand swap_exec_command_from_string(const char *s) _pure_;

const char* swap_result_to_string(SwapResult i) _const_;
SwapResult swap_result_from_string(const char *s) _pure_;

DEFINE_CAST(SWAP, Swap);
