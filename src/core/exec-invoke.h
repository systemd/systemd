/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct ExecCommand ExecCommand;
typedef struct ExecContext ExecContext;
typedef struct ExecParameters ExecParameters;
typedef struct ExecRuntime ExecRuntime;
typedef struct CGroupContext CGroupContext;

int exec_invoke(
                const ExecCommand *command,
                const ExecContext *context,
                ExecParameters *params,
                ExecRuntime *runtime,
                const CGroupContext *cgroup_context,
                int *exit_status);
