/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_send(const struct iovec_wrapper *iovw, int input_fd, PidRef *pidref, int mount_tree_fd);
int coredump_send_to_container(Context *context);
