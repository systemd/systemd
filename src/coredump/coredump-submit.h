/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int acquire_pid_mount_tree_fd(const Context *context, int *ret_fd);
int coredump_submit(
                const Context *context,
                struct iovec_wrapper *iovw,
                int input_fd);
