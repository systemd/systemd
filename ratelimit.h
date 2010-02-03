/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooratelimithfoo
#define fooratelimithfoo

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

#include "util.h"

typedef struct RateLimit {
        usec_t interval;
        unsigned burst;
        unsigned n_printed, n_missed;
        usec_t begin;
} RateLimit;

#define RATELIMIT_DEFINE(_name, _interval, _burst)       \
        RateLimit _name = {                              \
                .interval = (_interval),                 \
                .burst = (_burst),                       \
                .n_printed = 0,                          \
                .n_missed = 0,                           \
                .begin = 0                               \
        }

#define RATELIMIT_INIT(v, _interval, _burst)             \
        do {                                             \
                RateLimit *_r = &(v);                    \
                _r->interval = (_interval);              \
                _r->burst = (_burst);                    \
                _r->n_printed = 0;                       \
                _r->n_missed = 0;                        \
                _r->begin = 0;                           \
        } while (false);

bool ratelimit_test(RateLimit *r);

#endif
