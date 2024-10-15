/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/time.h>

#include "macro.h"
#include "ratelimit.h"

/* Modelled after Linux' lib/ratelimit.c by Dave Young
 * <hidave.darkstar@gmail.com>, which is licensed GPLv2. */

bool ratelimit_below(RateLimit *rl) {
        usec_t ts;

        assert(rl);

        if (!ratelimit_configured(rl))
                return true;

        ts = now(CLOCK_MONOTONIC);

        if (rl->begin <= 0 ||
            usec_sub_unsigned(ts, rl->begin) > rl->interval) {
                rl->begin = ts;  /* Start a new time window */
                rl->num = 1;     /* Reset counter */
                return true;
        }

        if (_unlikely_(rl->num == UINT_MAX))
                return false;

        rl->num++;
        return rl->num <= rl->burst;
}

unsigned ratelimit_num_dropped(const RateLimit *rl) {
        assert(rl);

        if (rl->num == UINT_MAX) /* overflow, return as special case */
                return UINT_MAX;

        return LESS_BY(rl->num, rl->burst);
}

usec_t ratelimit_end(const RateLimit *rl) {
        assert(rl);

        if (rl->begin == 0)
                return 0;

        return usec_add(rl->begin, rl->interval);
}

usec_t ratelimit_left(const RateLimit *rl) {
        assert(rl);

        if (rl->begin == 0)
                return 0;

        return usec_sub_unsigned(ratelimit_end(rl), now(CLOCK_MONOTONIC));
}
