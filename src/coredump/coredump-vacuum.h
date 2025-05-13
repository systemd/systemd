/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int coredump_vacuum(int exclude_fd, uint64_t keep_free, uint64_t max_use);
