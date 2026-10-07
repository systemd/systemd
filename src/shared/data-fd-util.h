/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int copy_data_fd(int fd);
int open_seekable_data_fd(const char *path);
int memfd_clone_fd(int fd, const char *name, int mode);
