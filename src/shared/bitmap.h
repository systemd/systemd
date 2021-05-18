/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "hashmap.h"
#include "macro.h"

typedef struct Bitmap {
        uint64_t *bitmaps;
        size_t n_bitmaps;
} Bitmap;

Bitmap* bitmap_new(void);
Bitmap* bitmap_copy(Bitmap *b);
int bitmap_ensure_allocated(Bitmap **b);
Bitmap* bitmap_free(Bitmap *b);

int bitmap_set(Bitmap *b, unsigned n);
void bitmap_unset(Bitmap *b, unsigned n);
bool bitmap_isset(const Bitmap *b, unsigned n);
bool bitmap_isclear(const Bitmap *b);
void bitmap_clear(Bitmap *b);

bool bitmap_iterate(const Bitmap *b, Iterator *i, unsigned *n);

bool bitmap_equal(const Bitmap *a, const Bitmap *b);

#define _BITMAP_FOREACH(n, b, i) \
        for (Iterator i = {}; bitmap_iterate((b), &i, (unsigned*)&(n)); )
#define BITMAP_FOREACH(n, b) \
        _BITMAP_FOREACH(n, b, UNIQ_T(i, UNIQ))

DEFINE_TRIVIAL_CLEANUP_FUNC(Bitmap*, bitmap_free);

#define _cleanup_bitmap_free_ _cleanup_(bitmap_freep)
