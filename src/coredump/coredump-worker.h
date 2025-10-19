/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_worker(const CoredumpConfig *config, int coredump_fd, bool request_mode, usec_t timestamp);
