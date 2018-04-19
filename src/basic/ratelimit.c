/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <sys/time.h>

#include "macro.h"
#include "ratelimit.h"

/* Modelled after Linux' lib/ratelimit.c by Dave Young
 * <hidave.darkstar@gmail.com>, which is licensed GPLv2. */

bool ratelimit_test(RateLimit *r) {
        usec_t ts;

        assert(r);

        if (r->interval <= 0 || r->burst <= 0)
                return true;

        ts = now(CLOCK_MONOTONIC);

        if (r->begin <= 0 ||
            r->begin + r->interval < ts) {
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
