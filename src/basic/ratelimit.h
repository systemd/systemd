/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct RateLimit {
        usec_t interval; /* Keep those two fields first so they can be initialized easily: */
        unsigned burst;  /* RateLimit rl = { INTERVAL, BURST }; */
        unsigned num;
        usec_t begin;
} RateLimit;

#define RATELIMIT_OFF (const RateLimit) { .interval = USEC_INFINITY, .burst = UINT_MAX }

static inline void ratelimit_reset(RateLimit *rl) {
        rl->num = rl->begin = 0;
}

static inline bool ratelimit_configured(const RateLimit *rl) {
        return rl->interval > 0 && rl->burst > 0;
}

bool ratelimit_below(RateLimit *rl);
/* Like ratelimit_below(), but takes the current CLOCK_BOOTTIME timestamp from the caller, for callers
 * that check many rate limits in a row and should not read the clock for each of them. The timestamps
 * passed for a given RateLimit must not go backwards: a ts before the one that opened the current
 * window makes usec_sub_unsigned() return 0, i.e. the window looks like it just started. */
bool ratelimit_below_at(RateLimit *rl, usec_t ts);

unsigned ratelimit_num_dropped(const RateLimit *rl);

usec_t ratelimit_end(const RateLimit *rl);
usec_t ratelimit_left(const RateLimit *rl);
