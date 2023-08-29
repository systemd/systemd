/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "time-util.h"

/* The default core dump rate limit interval */
#define DEFAULT_COREDUMP_RATE_LIMIT_INTERVAL 0

/* The default core dump rate limit burst */
#define DEFAULT_COREDUMP_RATE_LIMIT_BURST 5

/* The default maximum core dumps per boot */
#define DEFAULT_MAX_COREDUMPS_PER_BOOT 5

int coredump_ratelimit(const char *executable_path, usec_t interval, unsigned burst, unsigned max_coredumps_per_boot);