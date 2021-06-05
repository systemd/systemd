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
                r->begin = ts;

                /* Reset counter */
                r->num = 0;
                goto good;
        }

        if (r->num < r->burst)
                goto good;

        return false;

good:
        r->num++;
        return true;
}
