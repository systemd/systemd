/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "logarithm.h"
#include "tests.h"

TEST(LOG2ULL) {
        assert_se(LOG2ULL(0) == 0);
        assert_se(LOG2ULL(1) == 0);
        assert_se(LOG2ULL(8) == 3);
        assert_se(LOG2ULL(9) == 3);
        assert_se(LOG2ULL(15) == 3);
        assert_se(LOG2ULL(16) == 4);
        assert_se(LOG2ULL(1024*1024) == 20);
        assert_se(LOG2ULL(1024*1024+5) == 20);
}

TEST(CONST_LOG2ULL) {
        assert_se(CONST_LOG2ULL(0) == 0);
        assert_se(CONST_LOG2ULL(1) == 0);
        assert_se(CONST_LOG2ULL(8) == 3);
        assert_se(CONST_LOG2ULL(9) == 3);
        assert_se(CONST_LOG2ULL(15) == 3);
        assert_se(CONST_LOG2ULL(16) == 4);
        assert_se(CONST_LOG2ULL(1024*1024) == 20);
        assert_se(CONST_LOG2ULL(1024*1024+5) == 20);
}

TEST(NONCONST_LOG2ULL) {
        assert_se(NONCONST_LOG2ULL(0) == 0);
        assert_se(NONCONST_LOG2ULL(1) == 0);
        assert_se(NONCONST_LOG2ULL(8) == 3);
        assert_se(NONCONST_LOG2ULL(9) == 3);
        assert_se(NONCONST_LOG2ULL(15) == 3);
        assert_se(NONCONST_LOG2ULL(16) == 4);
        assert_se(NONCONST_LOG2ULL(1024*1024) == 20);
        assert_se(NONCONST_LOG2ULL(1024*1024+5) == 20);
}

TEST(log2u64) {
        assert_se(log2u64(0) == 0);
        assert_se(log2u64(1) == 0);
        assert_se(log2u64(8) == 3);
        assert_se(log2u64(9) == 3);
        assert_se(log2u64(15) == 3);
        assert_se(log2u64(16) == 4);
        assert_se(log2u64(1024*1024) == 20);
        assert_se(log2u64(1024*1024+5) == 20);
}

TEST(log2u) {
        assert_se(log2u(0) == 0);
        assert_se(log2u(1) == 0);
        assert_se(log2u(2) == 1);
        assert_se(log2u(3) == 1);
        assert_se(log2u(4) == 2);
        assert_se(log2u(32) == 5);
        assert_se(log2u(33) == 5);
        assert_se(log2u(63) == 5);
        assert_se(log2u(INT_MAX) == sizeof(int)*8-2);
}

TEST(log2i) {
        assert_se(log2i(0) == 0);
        assert_se(log2i(1) == 0);
        assert_se(log2i(2) == 1);
        assert_se(log2i(3) == 1);
        assert_se(log2i(4) == 2);
        assert_se(log2i(32) == 5);
        assert_se(log2i(33) == 5);
        assert_se(log2i(63) == 5);
        assert_se(log2i(INT_MAX) == sizeof(int)*8-2);
}

TEST(popcount) {
        uint16_t u16a = 0x0000;
        uint16_t u16b = 0xFFFF;
        uint32_t u32a = 0x00000010;
        uint32_t u32b = 0xFFFFFFFF;
        uint64_t u64a = 0x0000000000000010;
        uint64_t u64b = 0x0100000000100010;

        assert_se(popcount(u16a) == 0);
        assert_se(popcount(u16b) == 16);
        assert_se(popcount(u32a) == 1);
        assert_se(popcount(u32b) == 32);
        assert_se(popcount(u64a) == 1);
        assert_se(popcount(u64b) == 3);

        /* This would fail:
         * error: ‘_Generic’ selector of type ‘int’ is not compatible with any association
         * assert_se(popcount(0x10) == 1);
         */
}

DEFINE_TEST_MAIN(LOG_INFO);
