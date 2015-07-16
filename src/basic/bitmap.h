/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Tom Gundersen

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

#include "macro.h"
#include "hashmap.h"

typedef struct Bitmap Bitmap;

Bitmap *bitmap_new(void);

void bitmap_free(Bitmap *b);

int bitmap_ensure_allocated(Bitmap **b);

int bitmap_set(Bitmap *b, unsigned n);
void bitmap_unset(Bitmap *b, unsigned n);
bool bitmap_isset(Bitmap *b, unsigned n);
bool bitmap_isclear(Bitmap *b);
void bitmap_clear(Bitmap *b);

bool bitmap_iterate(Bitmap *b, Iterator *i, unsigned *n);

bool bitmap_equal(Bitmap *a, Bitmap *b);

#define BITMAP_FOREACH(n, b, i) \
        for ((i).idx = 0; bitmap_iterate((b), &(i), (unsigned*)&(n)); )

DEFINE_TRIVIAL_CLEANUP_FUNC(Bitmap*, bitmap_free);

#define _cleanup_bitmap_free_ _cleanup_(bitmap_freep)
