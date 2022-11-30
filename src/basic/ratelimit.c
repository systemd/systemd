/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/time.h>

#include "macro.h"
#include "ratelimit.h"

/* Modelled after Linux' lib/ratelimit.c by Dave Young
 * <hidave.darkstar@gmail.com>, which is licensed GPLv2. */

bool ratelimit_below(RateLimit *r) {
        usec_t ts;
        bool good = false;

        assert(r);

        if (!ratelimit_configured(r))
                return true;

        ts = now(CLOCK_MONOTONIC);

        if (r->begin <= 0 ||
            usec_sub_unsigned(ts, r->begin) > r->interval) {
                r->begin = ts;

                /* Reset counter */
                r->num = 0;
                good = true;
        } else if (r->num < r->burst)
                good = true;

        r->num++;
        return good;
}

unsigned ratelimit_num_dropped(RateLimit *r) {
        assert(r);

        return r->num > r->burst ? r->num - r->burst : 0;
}
