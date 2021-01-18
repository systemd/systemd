/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int coredump_ratelimit(const char* comm, usec_t interval, unsigned burst);
