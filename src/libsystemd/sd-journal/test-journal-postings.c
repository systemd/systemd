/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "journal-postings.h"
#include "random-util.h"
#include "sparse-endian.h"
#include "tests.h"

static void fill(bool *naive, PostingBitmap *b, PostingEncoder *e, uint64_t n, unsigned density) {
        for (uint64_t i = 0; i < n; i++) {
                /* Real posting lists have long runs, so make runs likely. */
                bool set = i > 0 && naive[i-1] ? random_u32() % 8 != 0 : random_u32() % density == 0;

                naive[i] = set;
                if (!set)
                        continue;

                posting_bitmap_set_range(b, i, 1);
                ASSERT_OK(posting_encoder_add(e, i));

                /* Adding the same posting twice must not change anything */
                if (random_u32() % 4 == 0)
                        ASSERT_OK(posting_encoder_add(e, i));
        }

        ASSERT_OK(posting_encoder_finish(e));
}

static void test_one(uint64_t n, unsigned density) {
        _cleanup_(posting_bitmap_done) PostingBitmap b = {}, decoded = {};
        _cleanup_(posting_encoder_done) PostingEncoder e = {};
        _cleanup_free_ bool *naive = NULL;
        uint64_t count = 0, start, length, v;
        PostingDecoder d;
        int r;

        ASSERT_NOT_NULL(naive = new0(bool, n + 1));
        ASSERT_OK(posting_bitmap_resize(&b, n));
        ASSERT_OK(posting_bitmap_resize(&decoded, n));

        fill(naive, &b, &e, n, density);

        for (uint64_t i = 0; i < n; i++) {
                ASSERT_EQ(posting_bitmap_isset(&b, i), naive[i]);
                count += naive[i];
        }

        ASSERT_EQ(e.n_postings, count);

        posting_decoder_init(&d, e.buffer, e.size, n);
        while ((r = posting_decoder_next(&d, &start, &length)) > 0) {
                ASSERT_GT(length, 0U);
                ASSERT_FALSE(posting_bitmap_isset(&decoded, start));
                posting_bitmap_set_range(&decoded, start, length);
        }
        ASSERT_OK(r);
        ASSERT_EQ(memcmp(b.words, decoded.words, POSTING_BITMAP_WORDS(n) * sizeof(uint64_t)), 0);

        /* A list that refers to entries beyond the end is invalid. */
        if (posting_bitmap_find_last(&b, 0, n, &v)) {
                posting_decoder_init(&d, e.buffer, e.size, v);
                while ((r = posting_decoder_next(&d, &start, &length)) > 0)
                        ;
                ASSERT_ERROR(r, EBADMSG);
        }

        /* Lookups */
        for (unsigned k = 0; k < 200; k++) {
                uint64_t from = random_u64_range(n + 1), to = random_u64_range(n + 2), c = 0, first = UINT64_MAX, last = UINT64_MAX;

                for (uint64_t i = from; i < MIN(to, n); i++) {
                        if (!naive[i])
                                continue;

                        if (first == UINT64_MAX)
                                first = i;
                        last = i;
                        c++;
                }

                ASSERT_EQ(posting_bitmap_find_first(&b, from, to, &v), c > 0);
                if (c > 0)
                        ASSERT_EQ(v, first);
                ASSERT_EQ(posting_bitmap_find_last(&b, from, to, &v), c > 0);
                if (c > 0)
                        ASSERT_EQ(v, last);
        }
}

TEST(postings) {
        unsigned n, density;

        FOREACH_ARGUMENT(n, 1U, 63U, 64U, 65U, 1000U, 4096U, 70001U)
                FOREACH_ARGUMENT(density, 1U, 2U, 17U, 1000U)
                        test_one(n, density);
}

static uint64_t decode_count(const PostingEncoder *e, uint64_t n, PostingBitmap *decoded) {
        uint64_t count;
        PostingDecoder d;

        posting_bitmap_clear_range(decoded, 0, decoded->n_bits);

        posting_decoder_init(&d, e->buffer, e->size, n);
        ASSERT_OK(posting_decoder_to_bitmap(&d, decoded, &count));

        return count;
}

TEST(snapshot) {
        _cleanup_(posting_bitmap_done) PostingBitmap decoded = {};
        _cleanup_(posting_encoder_done) PostingEncoder e = {}, first = {}, second = {}, final = {}, empty = {};
        const uint64_t n = 5000;

        ASSERT_OK(posting_bitmap_resize(&decoded, n));

        /* A snapshot in the middle of a run must neither change nor end the run */
        for (uint64_t i = 0; i < 100; i++)
                ASSERT_OK(posting_encoder_add(&e, i));

        ASSERT_OK(posting_encoder_snapshot(&e, &first));
        ASSERT_EQ(first.n_postings, 100U);
        ASSERT_EQ(decode_count(&first, n, &decoded), 100U);
        ASSERT_TRUE(posting_bitmap_isset(&decoded, 99));
        ASSERT_FALSE(posting_bitmap_isset(&decoded, 100));

        for (uint64_t i = 100; i < 200; i++)
                ASSERT_OK(posting_encoder_add(&e, i));
        for (uint64_t i = 300; i < 310; i++)
                ASSERT_OK(posting_encoder_add(&e, i));

        ASSERT_OK(posting_encoder_snapshot(&e, &second));
        ASSERT_EQ(decode_count(&second, n, &decoded), 210U);
        ASSERT_TRUE(posting_bitmap_isset(&decoded, 199));
        ASSERT_FALSE(posting_bitmap_isset(&decoded, 200));
        ASSERT_TRUE(posting_bitmap_isset(&decoded, 309));

        /* Snapshot of an empty encoder */
        ASSERT_OK(posting_encoder_snapshot(&final, &empty));
        ASSERT_EQ(empty.n_postings, 0U);
        ASSERT_EQ(decode_count(&empty, n, &decoded), 0U);

        ASSERT_OK(posting_encoder_add(&e, 4999));
        ASSERT_OK(posting_encoder_finish(&e));
        ASSERT_EQ(decode_count(&e, n, &decoded), 211U);
        ASSERT_TRUE(posting_bitmap_isset(&decoded, 4999));
}

TEST(add_run) {
        _cleanup_(posting_encoder_done) PostingEncoder e = {};
        uint64_t start, length;
        PostingDecoder d;

        /* Runs may overlap the previous run or extend it, but not start before it */
        ASSERT_OK(posting_encoder_add_run(&e, 10, 5));
        ASSERT_OK(posting_encoder_add_run(&e, 12, 10));
        ASSERT_OK(posting_encoder_add_run(&e, 14, 2));
        ASSERT_OK(posting_encoder_add_run(&e, 22, 1));
        ASSERT_ERROR(posting_encoder_add_run(&e, 9, 1), EINVAL);
        ASSERT_OK(posting_encoder_add_run(&e, 30, 3));
        ASSERT_ERROR(posting_encoder_add_run(&e, 20, 1), EINVAL);
        ASSERT_OK(posting_encoder_finish(&e));
        ASSERT_EQ(e.n_postings, 16U);

        posting_decoder_init(&d, e.buffer, e.size, 100);
        ASSERT_OK_POSITIVE(posting_decoder_next(&d, &start, &length));
        ASSERT_EQ(start, 10U);
        ASSERT_EQ(length, 13U);
        ASSERT_OK_POSITIVE(posting_decoder_next(&d, &start, &length));
        ASSERT_EQ(start, 30U);
        ASSERT_EQ(length, 3U);
        ASSERT_OK_ZERO(posting_decoder_next(&d, &start, &length));
}

TEST(combine) {
        _cleanup_(posting_bitmap_done) PostingBitmap a = {}, b = {};
        bool intersect;

        FOREACH_ARGUMENT(intersect, false, true) {
                posting_bitmap_done(&a);
                posting_bitmap_done(&b);
                ASSERT_OK(posting_bitmap_resize(&a, 200));
                ASSERT_OK(posting_bitmap_resize(&b, 200));
                posting_bitmap_set_range(&a, 10, 100);
                posting_bitmap_set_range(&b, 60, 100);

                posting_bitmap_combine(&a, &b, intersect);

                for (uint64_t i = 0; i < 200; i++) {
                        bool in_a = i >= 10 && i < 110, in_b = i >= 60 && i < 160;

                        ASSERT_EQ(posting_bitmap_isset(&a, i), intersect ? in_a && in_b : in_a || in_b);
                }
        }
}

TEST(merge_shifted) {
        static const uint64_t bits[] = { 0, 4, 5, 63, 64, 65, 127, 128, 199 };
        _cleanup_(posting_bitmap_done) PostingBitmap from = {}, to = {};
        uint64_t offset, skip;

        ASSERT_OK(posting_bitmap_resize(&from, 200));
        FOREACH_ELEMENT(i, bits)
                posting_bitmap_set_range(&from, *i, 1);

        FOREACH_ARGUMENT(offset, 0U, 1U, 63U, 64U, 70U, 128U) {
                FOREACH_ARGUMENT(skip, 0U, 5U, 64U, 65U, 199U, 200U) {
                        posting_bitmap_done(&to);
                        ASSERT_OK(posting_bitmap_resize(&to, 500));
                        posting_bitmap_set_range(&to, 0, 1);

                        posting_bitmap_merge_shifted(&to, offset, &from, skip);

                        for (uint64_t i = 0; i < 500; i++) {
                                bool expected = i == 0;

                                FOREACH_ELEMENT(j, bits)
                                        if (*j >= skip && i == *j + offset)
                                                expected = true;

                                ASSERT_EQ(posting_bitmap_isset(&to, i), expected);
                        }
                }
        }
}

TEST(invalid) {
        static const uint8_t truncated[] = { 0x01 },
                overlong[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00 },
                touching[] = { 0x00, 0x00, 0x00, 0x00 };
        uint64_t start, length;
        PostingDecoder d;

        posting_decoder_init(&d, truncated, sizeof(truncated), 100);
        ASSERT_ERROR(posting_decoder_next(&d, &start, &length), EBADMSG);

        posting_decoder_init(&d, overlong, sizeof(overlong), 100);
        ASSERT_ERROR(posting_decoder_next(&d, &start, &length), EBADMSG);

        posting_decoder_init(&d, touching, sizeof(touching), 100);
        ASSERT_OK_POSITIVE(posting_decoder_next(&d, &start, &length));
        ASSERT_ERROR(posting_decoder_next(&d, &start, &length), EBADMSG);

}

DEFINE_TEST_MAIN(LOG_INFO);
