/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_submit(
                const CoredumpConfig *config,
                const Context *context,
                struct iovec_wrapper *iovw,
                int input_fd);
