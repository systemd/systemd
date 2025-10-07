/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_process_request(int coredump_fd);
int coredump_process_socket(
                const CoredumpConfig *config,
                int coredump_fd,
                bool request_mode,
                usec_t timestamp,
                bool forwarded);
