/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int coredump_copy_records(int input_fd, int output_fd, uint64_t max_size);
