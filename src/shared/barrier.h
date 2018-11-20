/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"

/* See source file for an API description. */

typedef struct Barrier Barrier;

enum {
        BARRIER_SINGLE                  = 1LL,
        BARRIER_ABORTION                = INT64_MAX,

        /* bias values to store state; keep @WE < @THEY < @I */
        BARRIER_BIAS                    = INT64_MIN,
        BARRIER_WE_ABORTED              = BARRIER_BIAS + 1LL,
        BARRIER_THEY_ABORTED            = BARRIER_BIAS + 2LL,
        BARRIER_I_ABORTED               = BARRIER_BIAS + 3LL,
};

enum {
        BARRIER_PARENT,
        BARRIER_CHILD,
};

struct Barrier {
        int me;
        int them;
        int pipe[2];
        int64_t barriers;
};

#define BARRIER_NULL {-1, -1, {-1, -1}, 0}

int barrier_create(Barrier *obj);
void barrier_destroy(Barrier *b);

DEFINE_TRIVIAL_CLEANUP_FUNC(Barrier*, barrier_destroy);

void barrier_set_role(Barrier *b, unsigned role);

bool barrier_place(Barrier *b);
bool barrier_abort(Barrier *b);

bool barrier_wait_next(Barrier *b);
bool barrier_wait_abortion(Barrier *b);
bool barrier_sync_next(Barrier *b);
bool barrier_sync(Barrier *b);

static inline bool barrier_i_aborted(Barrier *b) {
        return IN_SET(b->barriers, BARRIER_I_ABORTED, BARRIER_WE_ABORTED);
}

static inline bool barrier_they_aborted(Barrier *b) {
        return IN_SET(b->barriers, BARRIER_THEY_ABORTED, BARRIER_WE_ABORTED);
}

static inline bool barrier_we_aborted(Barrier *b) {
        return b->barriers == BARRIER_WE_ABORTED;
}

static inline bool barrier_is_aborted(Barrier *b) {
        return IN_SET(b->barriers,
                      BARRIER_I_ABORTED, BARRIER_THEY_ABORTED, BARRIER_WE_ABORTED);
}

static inline bool barrier_place_and_sync(Barrier *b) {
        (void) barrier_place(b);
        return barrier_sync(b);
}
