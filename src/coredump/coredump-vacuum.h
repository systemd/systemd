/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <sys/types.h>

int coredump_vacuum(int exclude_fd, uint64_t keep_free, uint64_t max_use, const char *arg_coredump_path);
