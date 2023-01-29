/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "log.h"
#include "string-util.h"
#include "time-util.h"

#include "macro.h"

typedef struct slow_code_detector {
        usec_t timeout;
        unsigned line;
        const char *file;
        const char *func;
        bool valid;
} slow_code_detector;

static inline void slow_code(slow_code_detector *d) {
        if (d->timeout != USEC_INFINITY && d->timeout < now(CLOCK_MONOTONIC))
                log_debug("Detected overly slow code block in function %s() of %s: %u.", d->func, d->file, d->line);
}

#define PROFILE_SLOW_CODE(relative_timeout_usec) \
        _unused_ _cleanup_(slow_code) slow_code_detector detector_tmp = { \
                .timeout = DEBUG_LOGGING ? usec_add(now(CLOCK_MONOTONIC), (relative_timeout_usec)) : USEC_INFINITY, \
                .line = __LINE__,     \
                .file = __FILE__,     \
                .func = __FUNCTION__, \
                .valid = true         \
        }

#define WITH_PROFILE_SLOW_CODE(relative_timeout_usec)   \
        for (PROFILE_SLOW_CODE(relative_timeout_usec); detector_tmp.valid; detector_tmp.valid = false)
