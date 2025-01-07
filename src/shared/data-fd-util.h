/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

int copy_data_fd(int fd);
int memfd_clone_fd(int fd, const char *name, int mode);
