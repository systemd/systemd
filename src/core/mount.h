/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct Mount Mount;

#include "kill.h"
#include "dynamic-user.h"
#include "unit.h"

typedef enum MountExecCommand {
        MOUNT_EXEC_MOUNT,
        MOUNT_EXEC_UNMOUNT,
        MOUNT_EXEC_REMOUNT,
        _MOUNT_EXEC_COMMAND_MAX,
        _MOUNT_EXEC_COMMAND_INVALID = -1
} MountExecCommand;

typedef enum MountResult {
        MOUNT_SUCCESS,
        MOUNT_FAILURE_RESOURCES, /* a bit of a misnomer, just our catch-all error for errnos we didn't expect */
        MOUNT_FAILURE_TIMEOUT,
        MOUNT_FAILURE_EXIT_CODE,
        MOUNT_FAILURE_SIGNAL,
        MOUNT_FAILURE_CORE_DUMP,
        MOUNT_FAILURE_START_LIMIT_HIT,
        MOUNT_FAILURE_PROTOCOL,
        _MOUNT_RESULT_MAX,
        _MOUNT_RESULT_INVALID = -1
} MountResult;

typedef struct MountParameters {
        char *what;
        char *options;
        char *fstype;
} MountParameters;

/* Used while looking for mount points that vanished or got added from/to /proc/self/mountinfo */
typedef enum MountProcFlags {
        MOUNT_PROC_IS_MOUNTED   = 1 << 0,
        MOUNT_PROC_JUST_MOUNTED = 1 << 1,
        MOUNT_PROC_JUST_CHANGED = 1 << 2,
} MountProcFlags;

struct Mount {
        Unit meta;

        char *where;

        MountParameters parameters_proc_self_mountinfo;
        MountParameters parameters_fragment;

        bool from_proc_self_mountinfo:1;
        bool from_fragment:1;

        MountProcFlags proc_flags;

        bool sloppy_options;

        bool lazy_unmount;
        bool force_unmount;

        MountResult result;
        MountResult reload_result;
        MountResult clean_result;

        mode_t directory_mode;

        usec_t timeout_usec;

        ExecCommand exec_command[_MOUNT_EXEC_COMMAND_MAX];

        ExecContext exec_context;
        KillContext kill_context;
        CGroupContext cgroup_context;

        ExecRuntime *exec_runtime;
        DynamicCreds dynamic_creds;

        MountState state, deserialized_state;

        ExecCommand* control_command;
        MountExecCommand control_command_id;
        pid_t control_pid;

        sd_event_source *timer_event_source;

        unsigned n_retry_umount;
};

extern const UnitVTable mount_vtable;

void mount_fd_event(Manager *m, int events);

const char* mount_exec_command_to_string(MountExecCommand i) _const_;
MountExecCommand mount_exec_command_from_string(const char *s) _pure_;

const char* mount_result_to_string(MountResult i) _const_;
MountResult mount_result_from_string(const char *s) _pure_;

DEFINE_CAST(MOUNT, Mount);
