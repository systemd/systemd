/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int exec_invoke(
                const ExecCommand *command,
                const ExecContext *context,
                ExecParameters *params,
                ExecRuntime *runtime,
                const CGroupContext *cgroup_context,
                int *exit_status);
