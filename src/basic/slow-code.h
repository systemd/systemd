/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "log.h"
#include "string-util.h"
#include "time-util.h"

#include "macro.h"

typedef struct slow_code_detector {
        uint32_t timeout_sec;
        uint32_t count;
        usec_t current_time;
        size_t line_num;
        char *file;
        char *function;
} slow_code_detector;

static inline void slow_code(slow_code_detector *d) {
        if (d->current_time != USEC_INFINITY && d->current_time + d->timeout_sec * USEC_PER_SEC < now(CLOCK_MONOTONIC)) {
                log_debug("Detected overly slow code block in function %s() of %s: %" PRIu64 ".", d->function, d->file, d->line_num);
        }
        free(d->file);
        free(d->function);
}

#define PROFILE_SLOW_CODE(timeout_sec) \
        _cleanup_(slow_code) slow_code_detector detector_tmp = ((const slow_code_detector) {timeout_sec, 0,            \
                                                                 DEBUG_LOGGING ? now(CLOCK_MONOTONIC) : USEC_INFINITY, \
                                                                 __LINE__, strdup(__FILE__), strdup(__FUNCTION__)})

#define WITH_PROFILE_SLOW_CODE(timeout_sec) \
        for (PROFILE_SLOW_CODE(timeout_sec); detector_tmp.count < 1; detector_tmp.count++)
