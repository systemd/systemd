/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

void barrier_set_role(Barrier *b, unsigned int role);

bool barrier_place(Barrier *b);
bool barrier_abort(Barrier *b);

bool barrier_wait_next(Barrier *b);
bool barrier_wait_abortion(Barrier *b);
bool barrier_sync_next(Barrier *b);
bool barrier_sync(Barrier *b);

static inline bool barrier_i_aborted(Barrier *b) {
        return b->barriers == BARRIER_I_ABORTED || b->barriers == BARRIER_WE_ABORTED;
}

static inline bool barrier_they_aborted(Barrier *b) {
        return b->barriers == BARRIER_THEY_ABORTED || b->barriers == BARRIER_WE_ABORTED;
}

static inline bool barrier_we_aborted(Barrier *b) {
        return b->barriers == BARRIER_WE_ABORTED;
}

static inline bool barrier_is_aborted(Barrier *b) {
        return b->barriers == BARRIER_I_ABORTED || b->barriers == BARRIER_THEY_ABORTED || b->barriers == BARRIER_WE_ABORTED;
}

static inline bool barrier_place_and_sync(Barrier *b) {
        (void) barrier_place(b);
        return barrier_sync(b);
}
