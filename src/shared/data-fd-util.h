/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

enum {
        ACQUIRE_NO_DEV_NULL = 1 << 0,
        ACQUIRE_NO_MEMFD    = 1 << 1,
        ACQUIRE_NO_PIPE     = 1 << 2,
        ACQUIRE_NO_TMPFILE  = 1 << 3,
        ACQUIRE_NO_REGULAR  = 1 << 4,
};

int acquire_data_fd(const void *data, size_t size, unsigned flags);
int copy_data_fd(int fd);
int memfd_clone_fd(int fd, const char *name, int mode);
