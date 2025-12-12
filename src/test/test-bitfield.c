/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bitfield.h"
#include "tests.h"

#define TEST_BITS(bits, v, ...)                                         \
        ({                                                              \
                assert_se((!!BITS_SET(bits, ##__VA_ARGS__)) == v);     \
                assert_se((!!BITS_SET(~(bits), ##__VA_ARGS__)) == !v); \
        })
#define TEST_BIT(bits, v, i)                                            \
        ({                                                              \
                assert_se((!!BIT_SET(bits, i)) == v);                   \
                assert_se((!!BIT_SET(~(bits), i)) == !v);               \
                TEST_BITS(bits, v, i);                                  \
        })

#define TEST_BIT_SET(bits, i) TEST_BIT(bits, 1, i)
#define TEST_BIT_CLEAR(bits, i) TEST_BIT(bits, 0, i)

#define TEST_BITS_SET(bits, ...) TEST_BITS(bits, 1, ##__VA_ARGS__)
#define TEST_BITS_CLEAR(bits, ...) TEST_BITS(bits, 0, ##__VA_ARGS__)

TEST(bits) {
        int count;

        /* Test uint8_t */
        TEST_BIT_SET(0x81, 0);
        TEST_BIT_SET(0x81, 7);
        TEST_BITS_SET(0x81, 0, 7);
        TEST_BIT_CLEAR(0x81, 4);
        TEST_BIT_CLEAR(0x81, 6);
        TEST_BITS_CLEAR(0x81, 1, 2, 3, 4, 5, 6);
        uint8_t expected8 = 0;
        BIT_FOREACH(i, 0x81)
                expected8 |= UINT8_C(1) << i;
        assert_se(expected8 == 0x81);
        uint8_t u8 = 0x91;
        TEST_BIT_SET(u8, 4);
        TEST_BITS_SET(u8, 0, 4, 7);
        TEST_BIT_CLEAR(u8, 2);
        TEST_BITS_CLEAR(u8, 1, 2, 3, 5, 6);
        SET_BIT(u8, 1);
        TEST_BITS_SET(u8, 0, 1, 4, 7);
        TEST_BITS_CLEAR(u8, 2, 3, 5, 6);
        SET_BITS(u8, 3, 5);
        TEST_BITS_SET(u8, 0, 1, 3, 4, 5, 7);
        TEST_BITS_CLEAR(u8, 2, 6);
        CLEAR_BIT(u8, 4);
        TEST_BITS_SET(u8, 0, 1, 3, 5, 7);
        TEST_BITS_CLEAR(u8, 2, 4, 6);
        CLEAR_BITS(u8, 1);
        CLEAR_BITS(u8, 0, 7);
        TEST_BITS_SET(u8, 3, 5);
        TEST_BITS_CLEAR(u8, 0, 1, 2, 4, 6, 7);
        expected8 = 0;
        BIT_FOREACH(i, u8)
                expected8 |= UINT8_C(1) << i;
        assert_se(expected8 == u8);
        u8 = 0;
        TEST_BITS_CLEAR(u8, 0, 1, 2, 3, 4, 5, 6, 7);
        BIT_FOREACH(i, u8)
                assert_se(0);
        u8 = ~u8;
        TEST_BITS_SET(u8, 0, 1, 2, 3, 4, 5, 6, 7);
        count = 0;
        BIT_FOREACH(i, u8)
                count++;
        assert_se(count == 8);
        uint8_t _u8 = u8;
        SET_BITS(u8);
        assert_se(_u8 == u8);
        CLEAR_BITS(u8);
        assert_se(_u8 == u8);

        /* Test uint16_t */
        TEST_BIT_SET(0x1f81, 10);
        TEST_BITS_SET(0x1f81, 0, 7, 8, 9, 10, 11, 12);
        TEST_BIT_CLEAR(0x1f81, 13);
        TEST_BITS_CLEAR(0x1f81, 1, 2, 3, 4, 5, 6, 13, 14, 15);
        uint16_t expected16 = 0;
        BIT_FOREACH(i, 0x1f81)
                expected16 |= UINT16_C(1) << i;
        assert_se(expected16 == 0x1f81);
        uint16_t u16 = 0xf060;
        TEST_BIT_SET(u16, 12);
        TEST_BITS_SET(u16, 5, 6, 12, 13, 14, 15);
        TEST_BIT_CLEAR(u16, 9);
        TEST_BITS_CLEAR(u16, 0, 1, 2, 3, 4, 7, 8, 9, 10, 11);
        SET_BITS(u16, 1, 8);
        TEST_BITS_SET(u16, 1, 5, 6, 8, 12, 13, 14, 15);
        TEST_BITS_CLEAR(u16, 0, 2, 3, 4, 7, 9, 10, 11);
        CLEAR_BITS(u16, 13, 14);
        TEST_BITS_SET(u16, 1, 5, 6, 8, 12, 15);
        TEST_BITS_CLEAR(u16, 0, 2, 3, 4, 7, 9, 10, 11, 13, 14);
        expected16 = 0;
        BIT_FOREACH(i, u16)
                expected16 |= UINT16_C(1) << i;
        assert_se(expected16 == u16);
        u16 = 0;
        TEST_BITS_CLEAR(u16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        BIT_FOREACH(i, u16)
                assert_se(0);
        u16 = ~u16;
        TEST_BITS_SET(u16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        count = 0;
        BIT_FOREACH(i, u16)
                count++;
        assert_se(count == 16);
        uint16_t _u16 = u16;
        SET_BITS(u16);
        assert_se(_u16 == u16);
        CLEAR_BITS(u16);
        assert_se(_u16 == u16);

        /* Test uint32_t */
        TEST_BIT_SET(0x80224f10, 11);
        TEST_BITS_SET(0x80224f10, 4, 8, 9, 10, 11, 14, 17, 21, 31);
        TEST_BIT_CLEAR(0x80224f10, 28);
        TEST_BITS_CLEAR(0x80224f10, 0, 1, 2, 3, 5, 6, 7, 12, 13, 15, 16, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30);
        uint32_t expected32 = 0;
        BIT_FOREACH(i, 0x80224f10)
                expected32 |= UINT32_C(1) << i;
        assert_se(expected32 == 0x80224f10);
        uint32_t u32 = 0x605e0388;
        TEST_BIT_SET(u32, 3);
        TEST_BIT_SET(u32, 30);
        TEST_BITS_SET(u32, 3, 7, 8, 9, 17, 18, 19, 20, 22, 29, 30);
        TEST_BIT_CLEAR(u32, 0);
        TEST_BIT_CLEAR(u32, 31);
        TEST_BITS_CLEAR(u32, 0, 1, 2, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 21, 23, 24, 25, 26, 27, 28, 31);
        SET_BITS(u32, 1, 25, 26);
        TEST_BITS_SET(u32, 1, 3, 7, 8, 9, 17, 18, 19, 20, 22, 25, 26, 29, 30);
        TEST_BITS_CLEAR(u32, 0, 2, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 21, 23, 24, 27, 28, 31);
        CLEAR_BITS(u32, 29, 17, 1);
        TEST_BITS_SET(u32, 3, 7, 8, 9, 18, 19, 20, 22, 25, 26, 30);
        TEST_BITS_CLEAR(u32, 0, 1, 2, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 17, 21, 23, 24, 27, 28, 29, 31);
        expected32 = 0;
        BIT_FOREACH(i, u32)
                expected32 |= UINT32_C(1) << i;
        assert_se(expected32 == u32);
        u32 = 0;
        TEST_BITS_CLEAR(u32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
        BIT_FOREACH(i, u32)
                assert_se(0);
        u32 = ~u32;
        TEST_BITS_SET(u32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
        count = 0;
        BIT_FOREACH(i, u32)
                count++;
        assert_se(count == 32);
        uint32_t _u32 = u32;
        SET_BITS(u32);
        assert_se(_u32 == u32);
        CLEAR_BITS(u32);
        assert_se(_u32 == u32);

        /* Test uint64_t */
        TEST_BIT_SET(0x18ba1400f4857460, 60);
        TEST_BITS_SET(0x18ba1400f4857460, 5, 6, 10, 12, 13, 14, 16, 18, 23, 26, 28, 29, 30, 31, 42, 44, 49, 51, 52, 53, 55, 59, 60);
        TEST_BIT_CLEAR(UINT64_C(0x18ba1400f4857460), 0);
        TEST_BIT_CLEAR(UINT64_C(0x18ba1400f4857460), 63);
        TEST_BITS_CLEAR(UINT64_C(0x18ba1400f4857460), 0, 1, 2, 3, 4, 7, 8, 9, 11, 15, 17, 19, 20, 21, 22, 24, 25, 27, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 43, 45, 46, 47, 48, 50, 54, 56, 57, 58, 61, 62, 63);
        uint64_t expected64 = 0;
        BIT_FOREACH(i, 0x18ba1400f4857460)
                expected64 |= UINT64_C(1) << i;
        assert_se(expected64 == 0x18ba1400f4857460);
        uint64_t u64 = 0xa90e2d8507a65739;
        TEST_BIT_SET(u64, 0);
        TEST_BIT_SET(u64, 63);
        TEST_BITS_SET(u64, 0, 3, 4, 5, 8, 9, 10, 12, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 63);
        TEST_BIT_CLEAR(u64, 1);
        TEST_BITS_CLEAR(u64, 1, 2, 6, 7, 11, 13, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 38, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 62);
        SET_BIT(u64, 1);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 8, 9, 10, 12, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 63);
        TEST_BITS_CLEAR(u64, 2, 6, 7, 11, 13, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 38, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 62);
        CLEAR_BIT(u64, 63);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 8, 9, 10, 12, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61);
        TEST_BITS_CLEAR(u64, 2, 6, 7, 11, 13, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 38, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 62, 63);
        SET_BIT(u64, 62);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 8, 9, 10, 12, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 62);
        TEST_BITS_CLEAR(u64, 2, 6, 7, 11, 13, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 38, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 63);
        SET_BITS(u64, 63, 62, 7, 13, 38, 40);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 38, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 62, 63);
        TEST_BITS_CLEAR(u64, 2, 6, 11, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60);
        CLEAR_BIT(u64, 32);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14, 17, 18, 21, 23, 24, 25, 26, 34, 38, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 62, 63);
        TEST_BITS_CLEAR(u64, 2, 6, 11, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 32, 33, 35, 36, 37, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60);
        CLEAR_BITS(u64, 0, 2, 11, 63, 32, 58);
        TEST_BITS_SET(u64, 1, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14, 17, 18, 21, 23, 24, 25, 26, 34, 38, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 62);
        TEST_BITS_CLEAR(u64, 0, 2, 6, 11, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 32, 33, 35, 36, 37, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 63);
        expected64 = 0;
        BIT_FOREACH(i, u64)
                expected64 |= UINT64_C(1) << i;
        assert_se(expected64 == u64);
        u64 = 0;
        TEST_BITS_CLEAR(u64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);
        BIT_FOREACH(i, u64)
                assert_se(0);
        u64 = ~u64;
        TEST_BITS_SET(u64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);
        count = 0;
        BIT_FOREACH(i, u64)
                count++;
        assert_se(count == 64);
        uint64_t _u64 = u64;
        SET_BITS(u64);
        assert_se(_u64 == u64);
        CLEAR_BITS(u64);
        assert_se(_u64 == u64);

        /* Verify these use cases are constant-folded. */
#if !defined(__clang__) || (__clang_major__ >= 13)
        /* Clang 11 and 12 (and possibly older) do not grok those; skip them. */
        assert_cc(__builtin_constant_p(INDEX_TO_MASK(uint8_t, 1)));
        assert_cc(__builtin_constant_p(INDEX_TO_MASK(uint16_t, 1)));
        assert_cc(__builtin_constant_p(INDEX_TO_MASK(uint32_t, 1)));
        assert_cc(__builtin_constant_p(INDEX_TO_MASK(uint64_t, 1)));

        assert_cc(__builtin_constant_p(BIT_SET((uint8_t)2, 1)));
        assert_cc(__builtin_constant_p(BIT_SET((uint16_t)2, 1)));
        assert_cc(__builtin_constant_p(BIT_SET((uint32_t)2, 1)));
        assert_cc(__builtin_constant_p(BIT_SET((uint64_t)2, 1)));
#endif
}

DEFINE_TEST_MAIN(LOG_INFO);
