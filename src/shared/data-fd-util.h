/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int copy_data_fd_full(int fd, uint64_t max_size);
static inline int copy_data_fd(int fd) {
        return copy_data_fd_full(fd, UINT64_MAX);
}
int seekable_data_fd(int fd, uint64_t max_size);
int open_seekable_data_fd(int dir_fd, const char *path, uint64_t max_size);
int memfd_clone_fd(int fd, const char *name, int mode);
