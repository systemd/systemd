/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>

#include "ratelimit.h"
#include "log.h"

/* Modelled after Linux' lib/ratelimit.c by Dave Young
 * <hidave.darkstar@gmail.com>, which is licensed GPLv2. */

bool ratelimit_test(RateLimit *r) {
        usec_t ts;

        ts = now(CLOCK_MONOTONIC);

        assert(r);
        assert(r->interval > 0);
        assert(r->burst > 0);

        if (r->begin <= 0 ||
            r->begin + r->interval < ts) {

                if (r->n_missed > 0)
                        log_warning("%u events suppressed", r->n_missed);

                r->begin = ts;

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
