/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "journal-postings.h"
#include "unaligned.h"

#define VARINT_SIZE_MAX 10U

void posting_bitmap_done(PostingBitmap *b) {
        assert(b);

        b->words = mfree(b->words);
        b->n_bits = 0;
}

int posting_bitmap_resize(PostingBitmap *b, uint64_t n_bits) {
        assert(b);

        if (n_bits > SIZE_MAX - 63U)
                return -E2BIG;

        if (n_bits < b->n_bits)
                /* Bits beyond the end are always zero, so that growing again doesn't resurrect them. */
                posting_bitmap_clear_range(b, n_bits, b->n_bits - n_bits);
        else if (!GREEDY_REALLOC0(b->words, POSTING_BITMAP_WORDS(n_bits)))
                return -ENOMEM;

        b->n_bits = n_bits;
        return 0;
}

static uint64_t word_mask(uint64_t from, uint64_t to) {
        /* Requires 0 <= from < to <= 64 */
        uint64_t m = UINT64_MAX << from;

        if (to < 64)
                m &= (UINT64_C(1) << to) - 1;

        return m;
}

static bool clamp_range(const PostingBitmap *b, uint64_t *from, uint64_t *to) {
        assert(b);
        assert(from);
        assert(to);

        *to = MIN(*to, b->n_bits);
        return *from < *to;
}

static void posting_bitmap_modify_range(PostingBitmap *b, uint64_t start, uint64_t length, bool set) {
        uint64_t end;

        assert(b);

        if (length == 0 || start >= b->n_bits)
                return;

        end = length > b->n_bits - start ? b->n_bits : start + length;

        for (uint64_t w = start / 64; w * 64 < end; w++) {
                uint64_t m = word_mask(LESS_BY(start, w * 64),
                                       MIN(end - w * 64, UINT64_C(64)));

                if (set)
                        b->words[w] |= m;
                else
                        b->words[w] &= ~m;
        }
}

void posting_bitmap_set_range(PostingBitmap *b, uint64_t start, uint64_t length) {
        posting_bitmap_modify_range(b, start, length, /* set= */ true);
}

void posting_bitmap_clear_range(PostingBitmap *b, uint64_t start, uint64_t length) {
        posting_bitmap_modify_range(b, start, length, /* set= */ false);
}

bool posting_bitmap_find_first(const PostingBitmap *b, uint64_t from, uint64_t to, uint64_t *ret) {
        assert(b);

        if (!clamp_range(b, &from, &to))
                return false;

        for (uint64_t w = from / 64; w * 64 < to; w++) {
                uint64_t x = b->words[w] & word_mask(LESS_BY(from, w * 64),
                                                     MIN(to - w * 64, UINT64_C(64)));
                if (x == 0)
                        continue;

                if (ret)
                        *ret = w * 64 + __builtin_ctzll(x);
                return true;
        }

        return false;
}

bool posting_bitmap_find_last(const PostingBitmap *b, uint64_t from, uint64_t to, uint64_t *ret) {
        assert(b);

        if (!clamp_range(b, &from, &to))
                return false;

        for (uint64_t w = (to - 1) / 64 + 1; w > from / 64; w--) {
                uint64_t i = w - 1,
                         x = b->words[i] & word_mask(LESS_BY(from, i * 64),
                                                     MIN(to - i * 64, UINT64_C(64)));
                if (x == 0)
                        continue;

                if (ret)
                        *ret = i * 64 + 63 - __builtin_clzll(x);
                return true;
        }

        return false;
}

static size_t varint_encode(uint8_t *p, uint64_t v) {
        size_t n = 0;

        assert(p);

        while (v >= 0x80) {
                p[n++] = (uint8_t) v | 0x80;
                v >>= 7;
        }

        p[n++] = (uint8_t) v;
        return n;
}

static int varint_decode(const uint8_t **p, size_t *size, uint64_t *ret) {
        uint64_t v = 0;

        assert(p);
        assert(size);
        assert(ret);

        for (unsigned shift = 0;; shift += 7) {
                uint8_t c;

                if (*size == 0)
                        return -EBADMSG;
                if (shift >= 64)
                        return -EBADMSG;

                c = **p;
                (*p)++;
                (*size)--;

                if (shift == 63 && (c & 0x7e) != 0)
                        return -EBADMSG; /* doesn't fit into 64 bits */

                v |= (uint64_t) (c & 0x7f) << shift;

                if (!(c & 0x80))
                        break;
        }

        *ret = v;
        return 0;
}

void posting_encoder_done(PostingEncoder *e) {
        assert(e);

        e->buffer = mfree(e->buffer);
        *e = (PostingEncoder) {};
}

static int posting_encoder_flush(PostingEncoder *e) {
        assert(e);

        if (e->run_length == 0)
                return 0;

        if (!GREEDY_REALLOC(e->buffer, e->size + 2 * VARINT_SIZE_MAX))
                return -ENOMEM;

        assert(e->run_start >= e->previous_end);

        e->size += varint_encode(e->buffer + e->size, e->run_start - e->previous_end);
        e->size += varint_encode(e->buffer + e->size, e->run_length - 1);

        e->previous_end = e->run_start + e->run_length;
        e->run_length = 0;
        return 0;
}

int posting_encoder_add_run(PostingEncoder *e, uint64_t start, uint64_t length) {
        int r;

        assert(e);

        if (length == 0)
                return 0;
        if (length > UINT64_MAX - start)
                return -EINVAL;

        if (e->run_length > 0) {
                uint64_t end = e->run_start + e->run_length;

                /* Postings have to be added in ascending order. Adding the same posting again is fine
                 * though, as an entry might refer to the same data both directly and through a context. */
                if (start < e->run_start)
                        return -EINVAL;

                if (start <= end) {
                        if (start + length > end) {
                                e->n_postings += start + length - end;
                                e->run_length = start + length - e->run_start;
                        }

                        return 0;
                }

                r = posting_encoder_flush(e);
                if (r < 0)
                        return r;
        } else if (start < e->previous_end)
                return -EINVAL;

        e->run_start = start;
        e->run_length = length;
        e->n_postings += length;
        return 0;
}

int posting_encoder_finish(PostingEncoder *e) {
        return posting_encoder_flush(e);
}

int posting_encoder_snapshot(const PostingEncoder *e, PostingEncoder *ret) {
        assert(e);
        assert(ret);

        /* Returns a finished copy, so that postings can still be added to the original. */

        *ret = (PostingEncoder) {
                .size = e->size,
                .n_postings = e->n_postings,
                .run_start = e->run_start,
                .run_length = e->run_length,
                .previous_end = e->previous_end,
        };

        if (e->size > 0) {
                ret->buffer = memdup(e->buffer, e->size);
                if (!ret->buffer)
                        return -ENOMEM;
        }

        return posting_encoder_flush(ret);
}

int posting_decoder_init(
                PostingDecoder *d,
                PostingEncoding encoding,
                const void *p,
                size_t size,
                uint64_t inline_ordinal,
                uint64_t limit) {

        assert(d);

        switch (encoding) {

        case POSTING_INLINE:
                if (size != 0 || inline_ordinal >= limit)
                        return -EBADMSG;

                *d = (PostingDecoder) {
                        .encoding = encoding,
                        .limit = limit,
                        .position = inline_ordinal,
                        .size = 1, /* one posting left */
                };
                return 0;

        case POSTING_RLE:
                if (!p && size > 0)
                        return -EBADMSG;
                break;

        case POSTING_BITMAP:
                if (!p || size != POSTING_BITMAP_BYTES(limit))
                        return -EBADMSG;

                if (limit % 64 != 0 &&
                    (unaligned_read_le64((const uint8_t*) p + size - sizeof(uint64_t)) >> (limit % 64)) != 0)
                        return -EBADMSG;
                break;

        default:
                return -EBADMSG;
        }

        *d = (PostingDecoder) {
                .encoding = encoding,
                .p = p,
                .size = size,
                .limit = limit,
        };
        return 0;
}

static bool bitmap_bit(const uint8_t *p, uint64_t i) {
        return (unaligned_read_le64(p + i / 64 * sizeof(uint64_t)) >> (i % 64)) & 1U;
}

int posting_decoder_next(PostingDecoder *d, uint64_t *ret_start, uint64_t *ret_length) {
        uint64_t start, length;
        int r;

        assert(d);

        switch (d->encoding) {

        case POSTING_INLINE:
                if (d->size == 0)
                        return 0;

                d->size = 0;
                start = d->position;
                length = 1;
                break;

        case POSTING_RLE: {
                uint64_t gap;

                if (d->size == 0)
                        return 0;

                r = varint_decode(&d->p, &d->size, &gap);
                if (r < 0)
                        return r;

                r = varint_decode(&d->p, &d->size, &length);
                if (r < 0)
                        return r;

                /* Runs must not touch, only the first one may have a gap of zero. */
                if (gap == 0 && d->position > 0)
                        return -EBADMSG;
                if (gap >= d->limit - d->position)
                        return -EBADMSG;

                start = d->position + gap;

                if (length >= d->limit - start)
                        return -EBADMSG;

                length++;
                d->position = start + length;
                break;
        }

        case POSTING_BITMAP: {
                uint64_t i = d->position;

                while (i < d->limit && i % 64 == 0 &&
                       unaligned_read_le64(d->p + i / 64 * sizeof(uint64_t)) == 0)
                        i += 64;

                while (i < d->limit && !bitmap_bit(d->p, i)) {
                        i++;

                        while (i < d->limit && i % 64 == 0 &&
                               unaligned_read_le64(d->p + i / 64 * sizeof(uint64_t)) == 0)
                                i += 64;
                }

                if (i >= d->limit) {
                        d->position = d->limit;
                        return 0;
                }

                start = i;
                while (i < d->limit && bitmap_bit(d->p, i)) {
                        if (i % 64 == 0 && d->limit - i >= 64 &&
                            unaligned_read_le64(d->p + i / 64 * sizeof(uint64_t)) == UINT64_MAX)
                                i += 64;
                        else
                                i++;
                }

                length = i - start;
                d->position = i;
                break;
        }

        default:
                return -EBADMSG;
        }

        if (ret_start)
                *ret_start = start;
        if (ret_length)
                *ret_length = length;

        return 1;
}

int posting_decoder_to_bitmap(PostingDecoder *d, PostingBitmap *b, uint64_t *ret_n) {
        uint64_t start, length, n = 0;
        int r;

        assert(d);
        assert(b);

        while ((r = posting_decoder_next(d, &start, &length)) > 0) {
                posting_bitmap_set_range(b, start, length);
                n += length;
        }
        if (r < 0)
                return r;

        if (ret_n)
                *ret_n = n;
        return 0;
}
