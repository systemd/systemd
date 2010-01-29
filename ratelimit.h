/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooratelimithfoo
#define fooratelimithfoo

#include "util.h"

typedef struct RateLimit {
        usec_t interval;
        unsigned burst;
        unsigned n_printed, n_missed;
        usec_t begin;
} RateLimit;

#define RATELIMIT_DEFINE(_name, _interval, _burst)      \
        RateLimit _name = {                             \
                .interval = (_interval),                \
                .burst = (_burst),                      \
                .n_printed = 0,                         \
                .n_missed = 0,                          \
                .begin = 0                              \
        }

#define RATELIMIT_INIT(v, _interval, _burst)            \
        do {                                            \
                RateLimit *r = &(v);                    \
                r->interval = (_interval);              \
                r->burst = (_burst);                    \
                r->n_printed = 0;                       \
                r->n_missed = 0;                        \
                r->begin = 0;                           \
        } while (false);

bool ratelimit_test(RateLimit *r);

#endif
