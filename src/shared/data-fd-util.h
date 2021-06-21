/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

int acquire_data_fd(const void *data, size_t size, unsigned flags);
int copy_data_fd(int fd);
