/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/time.h>

#include "macro.h"
#include "ratelimit.h"

/* Modelled after Linux' lib/ratelimit.c by Dave Young
 * <hidave.darkstar@gmail.com>, which is licensed GPLv2. */

bool ratelimit_below(RateLimit *r) {
        usec_t ts;

        assert(r);

        if (!ratelimit_configured(r))
                return true;

        ts = now(CLOCK_MONOTONIC);

        if (r->begin <= 0 ||
            usec_sub_unsigned(ts, r->begin) > r->interval) {
                r->begin = ts;  /* Start a new time window */
                r->num = 1;     /* Reset counter */
                return true;
        }

        if (_unlikely_(r->num == UINT_MAX))
                return false;

        r->num++;
        return r->num <= r->burst;
}

unsigned ratelimit_num_dropped(RateLimit *r) {
        assert(r);

        if (r->num == UINT_MAX) /* overflow, return as special case */
                return UINT_MAX;

        return LESS_BY(r->num, r->burst);
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
