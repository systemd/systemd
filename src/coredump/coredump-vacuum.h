/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering
***/

#include <inttypes.h>
#include <sys/types.h>

int coredump_vacuum(int exclude_fd, uint64_t keep_free, uint64_t max_use);
