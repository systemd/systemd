/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "time-util.h"

/* The default core dump rate-limit interval */
#define DEFAULT_COREDUMP_RATELIMIT_INTERVAL 0

/* The default core dump rate-limit burst */
#define DEFAULT_COREDUMP_RATELIMIT_BURST    0

int coredump_ratelimit(const char* comm, usec_t interval, unsigned burst);
