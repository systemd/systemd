/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int acquire_pid_mount_tree_fd(const CoredumpConfig *config, CoredumpContext *context);
int coredump_submit(const CoredumpConfig *config, CoredumpContext *context);
