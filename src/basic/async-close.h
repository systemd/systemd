/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int asynchronous_close(int fd);
void asynchronous_close_many(const int fds[], size_t n_fds);

DEFINE_TRIVIAL_CLEANUP_FUNC(int, asynchronous_close);
