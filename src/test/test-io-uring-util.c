/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "io-uring-util.h"
#include "tests.h"

static bool io_uring_init_or_skip(IoUring *ring, unsigned entries) {
        int r;

        r = io_uring_init(ring, entries, /* flags= */ 0);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r)) {
                log_tests_skipped_errno(r, "io_uring unavailable");
                return false;
        }
        ASSERT_OK(r);

        return true;
}

static void queue_nops(IoUring *ring, unsigned n, uint64_t first_id) {
        for (unsigned i = 0; i < n; i++) {
                struct io_uring_sqe *sqe = ASSERT_NOT_NULL(io_uring_get_sqe(ring));
                io_uring_prep_nop(sqe);
                sqe->user_data = first_id + i;
        }
}

static unsigned reap(IoUring *ring, bool *seen, size_t n_seen) {
        struct io_uring_cqe *cqe;
        unsigned n = 0;

        IO_URING_FOREACH_CQE(cqe, ring) {
                ASSERT_EQ(cqe->res, 0);
                ASSERT_LT(cqe->user_data, (uint64_t) n_seen);
                ASSERT_FALSE(seen[cqe->user_data]);
                seen[cqe->user_data] = true;
                n++;
        }
        io_uring_cq_advance(ring, n);

        return n;
}

TEST(sq_full) {
        _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;

        if (!io_uring_init_or_skip(&ring, 4))
                return;

        queue_nops(&ring, 4, 0);
        ASSERT_NULL(io_uring_get_sqe(&ring));

        ASSERT_OK_EQ(io_uring_submit(&ring), 4);
        ASSERT_NOT_NULL(io_uring_get_sqe(&ring));
}

TEST(wrap_around) {
        _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
        bool seen[4 * 25] = {};

        if (!io_uring_init_or_skip(&ring, 4))
                return;

        /* Each round fills the whole SQ ring. After a few rounds, the SQ and CQ indices are larger than the
         * ring sizes, so every slot was used more than once. */
        for (unsigned round = 0; round < 25; round++) {
                queue_nops(&ring, 4, round * 4);
                ASSERT_OK_EQ(io_uring_submit(&ring), 4);
                ASSERT_EQ(io_uring_cq_ready(&ring), 4u);
                ASSERT_EQ(reap(&ring, seen, ELEMENTSOF(seen)), 4u);
        }

        FOREACH_ELEMENT(i, seen)
                ASSERT_TRUE(*i);
}

TEST(cq_overflow) {
        _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
        bool seen[4 * 8] = {};
        unsigned n = 0;

        if (!io_uring_init_or_skip(&ring, 4))
                return;

        /* The CQ ring has twice as many entries as the SQ ring. Without reaping, the CQEs after the first 8
         * go to the overflow list of the kernel. io_uring_submit() has to move them back into the CQ ring,
         * otherwise they are never seen. */
        for (unsigned round = 0; round < 8; round++) {
                queue_nops(&ring, 4, round * 4);
                ASSERT_OK_EQ(io_uring_submit(&ring), 4);
        }

        for (unsigned attempt = 0; n < ELEMENTSOF(seen); attempt++) {
                ASSERT_LT(attempt, 100u);
                n += reap(&ring, seen, ELEMENTSOF(seen));
                ASSERT_OK(io_uring_submit(&ring));
        }

        ASSERT_EQ(n, ELEMENTSOF(seen));
        ASSERT_EQ(io_uring_cq_ready(&ring), 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
