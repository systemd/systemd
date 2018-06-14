/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "time-util.h"
#include "util.h"

typedef struct RateLimit {
        usec_t interval;
        usec_t begin;
        unsigned burst;
        unsigned num;
} RateLimit;

#define RATELIMIT_DEFINE(_name, _interval, _burst)       \
        RateLimit _name = {                              \
                .interval = (_interval),                 \
                .burst = (_burst),                       \
                .num = 0,                                \
                .begin = 0                               \
        }

#define RATELIMIT_INIT(v, _interval, _burst)             \
        do {                                             \
                RateLimit *_r = &(v);                    \
                _r->interval = (_interval);              \
                _r->burst = (_burst);                    \
                _r->num = 0;                             \
                _r->begin = 0;                           \
        } while (false)

#define RATELIMIT_RESET(v)                               \
        do {                                             \
                RateLimit *_r = &(v);                    \
                _r->num = 0;                             \
                _r->begin = 0;                           \
        } while (false)

bool ratelimit_below(RateLimit *r);
