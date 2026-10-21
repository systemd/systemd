/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Posting lists of segmented journal files hold ordinals relative to the segment, ascending. On disk they are
 * run-length encoded. Readers expand them into bitmaps. */

typedef struct PostingBitmap {
        uint64_t *words;
        uint64_t n_bits;
} PostingBitmap;

#define POSTING_BITMAP_WORDS(n_bits) DIV_ROUND_UP(n_bits, 64U)

void posting_bitmap_done(PostingBitmap *b);
int posting_bitmap_resize(PostingBitmap *b, uint64_t n_bits); /* only grows */

static inline bool posting_bitmap_isset(const PostingBitmap *b, uint64_t i) {
        return i < b->n_bits && (b->words[i / 64] >> (i % 64)) & 1U;
}

void posting_bitmap_set_range(PostingBitmap *b, uint64_t start, uint64_t length);
void posting_bitmap_clear_range(PostingBitmap *b, uint64_t start, uint64_t length);

/* Only bits in [from, to) are considered. Returns false if none of them is set. */
bool posting_bitmap_find_first(const PostingBitmap *b, uint64_t from, uint64_t to, uint64_t *ret);
bool posting_bitmap_find_last(const PostingBitmap *b, uint64_t from, uint64_t to, uint64_t *ret);

/* Both bitmaps have the same size */
void posting_bitmap_combine(PostingBitmap *a, const PostingBitmap *b, bool intersect);

/* Sets the bits of 'from' that are not below 'skip' in 'to', moved up by 'offset' */
void posting_bitmap_merge_shifted(PostingBitmap *to, uint64_t offset, const PostingBitmap *from, uint64_t skip);

/* Builds a run-length encoded posting list. */
typedef struct PostingEncoder {
        uint8_t *buffer;
        size_t size;
        uint64_t n_postings;

        uint64_t run_start;
        uint64_t run_length;
        uint64_t previous_end; /* end of the last run that was written to the buffer */
} PostingEncoder;

void posting_encoder_done(PostingEncoder *e);
int posting_encoder_add_run(PostingEncoder *e, uint64_t start, uint64_t length);
static inline int posting_encoder_add(PostingEncoder *e, uint64_t ordinal) {
        return posting_encoder_add_run(e, ordinal, 1);
}
int posting_encoder_finish(PostingEncoder *e);
int posting_encoder_snapshot(const PostingEncoder *e, PostingEncoder *ret);

/* Iterates over the runs of an encoded posting list. 'limit' is the number of entries of the segment:
 * ordinals at or beyond it are refused. */
typedef struct PostingDecoder {
        const uint8_t *p;
        size_t size;
        uint64_t limit;
        uint64_t position;
} PostingDecoder;

void posting_decoder_init(PostingDecoder *d, const void *p, size_t size, uint64_t limit);

/* Returns > 0 and the next run, 0 at the end, or a negative error if the list is invalid. */
int posting_decoder_next(PostingDecoder *d, uint64_t *ret_start, uint64_t *ret_length);
int posting_decoder_to_bitmap(PostingDecoder *d, PostingBitmap *b, uint64_t *ret_n);
