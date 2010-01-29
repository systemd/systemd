/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>

#include "ratelimit.h"
#include "log.h"

/* Modelled after Linux' lib/ratelimit.c by Dave Young
 * <hidave.darkstar@gmail.com>, which is licensed GPLv2. */

bool ratelimit_test(RateLimit *r) {
        usec_t timestamp;

        timestamp = now(CLOCK_MONOTONIC);

        assert(r);
        assert(r->interval > 0);
        assert(r->burst > 0);

        if (r->begin <= 0 ||
            r->begin + r->interval < timestamp) {

                if (r->n_missed > 0)
                        log_warning("%u events suppressed", r->n_missed);

                r->begin = timestamp;

                /* Reset counters */
                r->n_printed = 0;
                r->n_missed = 0;
                goto good;
        }

        if (r->n_printed <= r->burst)
                goto good;

        r->n_missed++;
        return false;

good:
        r->n_printed++;
        return true;
}
