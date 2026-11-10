/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "errno-util.h"
#include "io-uring-util.h"
#include "tests.h"
#include "time-util.h"

static bool io_uring_init_or_skip(IoUring *ring, unsigned entries) {
        int r;

        r = io_uring_init(ring, entries, /* flags= */ 0);
        /* Kernels without SQE128 and CQE32 support reject the setup flags with EINVAL. */
        if (r == -EINVAL || ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r)) {
                log_tests_skipped_errno(r, "io_uring unavailable");
                return false;
        }
        ASSERT_OK(r);

        return true;
}

static void queue_nops(IoUring *ring, unsigned n, uint64_t first_id) {
        for (unsigned i = 0; i < n; i++) {
                union io_uring_sqe128 *sqe = ASSERT_NOT_NULL(io_uring_get_sqe(ring));
                io_uring_prep_nop(&sqe->sqe);
                sqe->sqe.user_data = first_id + i;
        }
}

static unsigned reap(IoUring *ring, bool *seen, size_t n_seen) {
        union io_uring_cqe32 *cqe;
        unsigned n = 0;

        IO_URING_FOREACH_CQE(cqe, ring) {
                ASSERT_EQ(cqe->cqe.res, 0);
                ASSERT_LT(cqe->cqe.user_data, (uint64_t) n_seen);
                ASSERT_FALSE(seen[cqe->cqe.user_data]);
                seen[cqe->cqe.user_data] = true;
                n++;
        }
        io_uring_cq_advance(ring, n);

        return n;
}

TEST(sq_full) {
        _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;

        if (!io_uring_init_or_skip(&ring, 4))
                return;

        queue_nops(&ring, 4, /* first_id= */ 0);
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

TEST(submit_and_wait) {
        _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
        bool seen[1] = {};

        if (!io_uring_init_or_skip(&ring, 4))
                return;

        ASSERT_ERROR(io_uring_submit_and_wait(&ring, 10 * USEC_PER_MSEC), ETIME);

        queue_nops(&ring, 1, /* first_id= */ 0);
        ASSERT_OK_EQ(io_uring_submit_and_wait(&ring, USEC_INFINITY), 1);
        ASSERT_EQ(reap(&ring, seen, ELEMENTSOF(seen)), 1u);
        ASSERT_TRUE(seen[0]);
}

TEST(sqe_cleared) {
        _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
        bool seen[4 * 25] = {};

        if (!io_uring_init_or_skip(&ring, 4))
                return;

        for (unsigned round = 0; round < 25; round++) {
                for (unsigned i = 0; i < 4; i++) {
                        union io_uring_sqe128 *sqe = ASSERT_NOT_NULL(io_uring_get_sqe(&ring));
                        FOREACH_ELEMENT(byte, sqe->raw)
                                ASSERT_EQ(*byte, 0u);

                        memset(sqe->raw + sizeof(sqe->sqe), 0xff, sizeof(*sqe) - sizeof(sqe->sqe));
                        io_uring_prep_nop(&sqe->sqe);
                        sqe->sqe.user_data = round * 4 + i;
                }
                ASSERT_OK_EQ(io_uring_submit(&ring), 4);
                ASSERT_EQ(reap(&ring, seen, ELEMENTSOF(seen)), 4u);
        }
}

TEST(cqe32_payload) {
        /* A ring with 256 entries must return the distinct extended results of 256 NOPs in submission order.
         * Only the first completion may skip the test when the kernel lacks IORING_NOP_CQE32 support. */
        _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
        union io_uring_cqe32 *cqe;
        unsigned n = 0;

        if (!io_uring_init_or_skip(&ring, 256))
                return;

        for (unsigned i = 0; i < 256; i++) {
                union io_uring_sqe128 *sqe = ASSERT_NOT_NULL(io_uring_get_sqe(&ring));
                io_uring_prep_nop(&sqe->sqe);
                sqe->sqe.nop_flags = IORING_NOP_CQE32 | IORING_NOP_INJECT_RESULT;
                sqe->sqe.len = 1;
                sqe->sqe.off = UINT64_MAX - i;
                sqe->sqe.addr = UINT64_C(0x123456789abcdef0) + i;
                sqe->sqe.user_data = i;
                ASSERT_OK_EQ(io_uring_submit(&ring), 1);

                IO_URING_FOREACH_CQE(cqe, &ring) {
                        /* Older kernels ignore nop_flags and return 0 instead of the injected result. */
                        if (i == 0 && IN_SET(cqe->cqe.res, 0, -EINVAL)) {
                                log_tests_skipped("IORING_NOP_CQE32 unavailable");
                                return;
                        }
                        ASSERT_EQ(cqe->cqe.res, 1);
                        ASSERT_EQ(cqe->cqe.user_data, i);
                        ASSERT_EQ(cqe->cqe.big_cqe[0], UINT64_MAX - i);
                        ASSERT_EQ(cqe->cqe.big_cqe[1], UINT64_C(0x123456789abcdef0) + i);
                        n++;
                }
                ASSERT_EQ(n, i + 1);
                io_uring_cq_advance(&ring, 1);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
