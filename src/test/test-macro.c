/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"

TEST(saturate_add) {
        ASSERT_EQ(saturate_add(1, 2, UINT8_MAX), 3);
        ASSERT_EQ(saturate_add(1, UINT8_MAX-2, UINT8_MAX), UINT8_MAX-1);
        ASSERT_EQ(saturate_add(1, UINT8_MAX-1, UINT8_MAX), UINT8_MAX);
        ASSERT_EQ(saturate_add(1, UINT8_MAX, UINT8_MAX), UINT8_MAX);
        ASSERT_EQ(saturate_add(2, UINT8_MAX, UINT8_MAX), UINT8_MAX);
        ASSERT_EQ(saturate_add(60, 60, 50), 50);
}

TEST(ALIGN_POWER2) {
        unsigned long i, p2;

        ASSERT_EQ(ALIGN_POWER2(0), 0U);
        ASSERT_EQ(ALIGN_POWER2(1), 1U);
        ASSERT_EQ(ALIGN_POWER2(2), 2U);
        ASSERT_EQ(ALIGN_POWER2(3), 4U);
        ASSERT_EQ(ALIGN_POWER2(4), 4U);
        ASSERT_EQ(ALIGN_POWER2(5), 8U);
        ASSERT_EQ(ALIGN_POWER2(6), 8U);
        ASSERT_EQ(ALIGN_POWER2(7), 8U);
        ASSERT_EQ(ALIGN_POWER2(9), 16U);
        ASSERT_EQ(ALIGN_POWER2(10), 16U);
        ASSERT_EQ(ALIGN_POWER2(11), 16U);
        ASSERT_EQ(ALIGN_POWER2(12), 16U);
        ASSERT_EQ(ALIGN_POWER2(13), 16U);
        ASSERT_EQ(ALIGN_POWER2(14), 16U);
        ASSERT_EQ(ALIGN_POWER2(15), 16U);
        ASSERT_EQ(ALIGN_POWER2(16), 16U);
        ASSERT_EQ(ALIGN_POWER2(17), 32U);

        ASSERT_EQ(ALIGN_POWER2(ULONG_MAX), 0U);
        ASSERT_EQ(ALIGN_POWER2(ULONG_MAX - 1), 0U);
        ASSERT_EQ(ALIGN_POWER2(ULONG_MAX - 1024), 0U);
        ASSERT_EQ(ALIGN_POWER2(ULONG_MAX / 2), ULONG_MAX / 2 + 1);
        ASSERT_EQ(ALIGN_POWER2(ULONG_MAX + 1), 0U);

        for (i = 1; i < 131071; ++i) {
                for (p2 = 1; p2 < i; p2 <<= 1)
                        /* empty */ ;

                ASSERT_EQ(ALIGN_POWER2(i), p2);
        }

        for (i = ULONG_MAX - 1024; i < ULONG_MAX; ++i) {
                for (p2 = 1; p2 && p2 < i; p2 <<= 1)
                        /* empty */ ;

                ASSERT_EQ(ALIGN_POWER2(i), p2);
        }
}

TEST(MAX) {
        static const struct {
                int a;
                int b[CONST_MAX(10, 100)];
        } val1 = {
                .a = CONST_MAX(10, 100),
        };
        int d = 0;
        unsigned long x = 12345;
        unsigned long y = 54321;
        const char str[] = "a_string_constant";
        const unsigned long long arr[] = {9999ULL, 10ULL, 0ULL, 3000ULL, 2000ULL, 1000ULL, 100ULL, 9999999ULL};
        void *p = (void *)str;
        void *q = (void *)&str[16];

        assert_cc(sizeof(val1.b) == sizeof(int) * 100);

        /* CONST_MAX returns (void) instead of a value if the passed arguments
         * are not of the same type or not constant expressions. */
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 10)), int));
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 1U)), typeof(VOID_0)));

        ASSERT_EQ(val1.a, 100);
        ASSERT_EQ(MAX(++d, 0), 1);
        ASSERT_EQ(d, 1);

        assert_cc(MAXSIZE(char[3], uint16_t) == 3);
        assert_cc(MAXSIZE(char[3], uint32_t) == 4);
        assert_cc(MAXSIZE(char, long) == sizeof(long));

        ASSERT_EQ(MAX(-5, 5), 5);
        ASSERT_EQ(MAX(5, 5), 5);
        ASSERT_EQ(MAX(MAX(1, MAX(2, MAX(3, 4))), 5), 5);
        ASSERT_EQ(MAX(MAX(1, MAX(2, MAX(3, 2))), 1), 3);
        ASSERT_EQ(MAX(MIN(1, MIN(2, MIN(3, 4))), 5), 5);
        ASSERT_EQ(MAX(MAX(1, MIN(2, MIN(3, 2))), 1), 2);
        ASSERT_EQ(LESS_BY(8, 4), 4);
        ASSERT_EQ(LESS_BY(8, 8), 0);
        ASSERT_EQ(LESS_BY(4, 8), 0);
        ASSERT_EQ(LESS_BY(16, LESS_BY(8, 4)), 12);
        ASSERT_EQ(LESS_BY(4, LESS_BY(8, 4)), 0);
        ASSERT_EQ(CMP(3, 5), -1);
        ASSERT_EQ(CMP(5, 3), 1);
        ASSERT_EQ(CMP(5, 5), 0);
        ASSERT_EQ(CMP(x, y), -1);
        ASSERT_EQ(CMP(y, x), 1);
        ASSERT_EQ(CMP(x, x), 0);
        ASSERT_EQ(CMP(y, y), 0);
        ASSERT_EQ(CMP(UINT64_MAX, (uint64_t) 0), 1);
        ASSERT_EQ(CMP((uint64_t) 0, UINT64_MAX), -1);
        ASSERT_EQ(CMP(UINT64_MAX, UINT64_MAX), 0);
        ASSERT_EQ(CMP(INT64_MIN, INT64_MAX), -1);
        ASSERT_EQ(CMP(INT64_MAX, INT64_MIN), 1);
        ASSERT_EQ(CMP(INT64_MAX, INT64_MAX), 0);
        ASSERT_EQ(CMP(INT64_MIN, INT64_MIN), 0);
        ASSERT_EQ(CMP(INT64_MAX, (int64_t) 0), 1);
        ASSERT_EQ(CMP((int64_t) 0, INT64_MIN), 1);
        ASSERT_EQ(CMP(INT64_MIN, (int64_t) 0), -1);
        ASSERT_EQ(CMP((int64_t) 0, INT64_MAX), -1);
        ASSERT_EQ(CMP(&str[2], &str[7]), -1);
        ASSERT_EQ(CMP(&str[2], &str[2]), 0);
        ASSERT_EQ(CMP(&str[7], (const char *)str), 1);
        ASSERT_EQ(CMP(str[2], str[7]), 1);
        ASSERT_EQ(CMP(str[7], *str), 1);
        ASSERT_EQ(CMP((const unsigned long long *)arr, &arr[3]), -1);
        ASSERT_EQ(CMP(*arr, arr[3]), 1);
        ASSERT_EQ(CMP(p, q), -1);
        ASSERT_EQ(CMP(q, p), 1);
        ASSERT_EQ(CMP(p, p), 0);
        ASSERT_EQ(CMP(q, q), 0);
        ASSERT_EQ(CLAMP(-5, 0, 1), 0);
        ASSERT_EQ(CLAMP(5, 0, 1), 1);
        ASSERT_EQ(CLAMP(5, -10, 1), 1);
        ASSERT_EQ(CLAMP(5, -10, 10), 5);
        ASSERT_EQ(CLAMP(CLAMP(0, -10, 10), CLAMP(-5, 10, 20), CLAMP(100, -5, 20)), 10);
}

TEST(ABS_DIFF) {
        ASSERT_EQ(ABS_DIFF(5, 3), 2);
        ASSERT_EQ(ABS_DIFF(3, 5), 2);
        ASSERT_EQ(ABS_DIFF(5llu, 2llu), 3llu);
        ASSERT_EQ(ABS_DIFF(3llu, 5llu), 2llu);
}

#pragma GCC diagnostic push
#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

TEST(container_of) {
        struct mytype {
                uint8_t pad1[3];
                uint64_t v1;
                uint8_t pad2[2];
                uint32_t v2;
        } myval = { };

        assert_cc(sizeof(myval) >= 17);
        ASSERT_PTR_EQ(container_of(&myval.v1, struct mytype, v1), &myval);
        ASSERT_PTR_EQ(container_of(&myval.v2, struct mytype, v2), &myval);
        ASSERT_PTR_EQ(container_of(&container_of(&myval.v2,
                                                 struct mytype,
                                                 v2)->v1,
                                   struct mytype,
                                   v1), &myval);
}

#pragma GCC diagnostic pop

#define TEST_OVERFLOW_MATH_BY_TYPE(type, min, max, lit)                 \
        ({                                                              \
                type x;                                                 \
                                                                        \
                ASSERT_TRUE(ADD_SAFE(&x, lit(5), lit(10)));             \
                ASSERT_EQ(x, lit(15));                                  \
                if (IS_SIGNED_INTEGER_TYPE(type)) {                     \
                        ASSERT_TRUE(ADD_SAFE(&x, lit(5), lit(-10)));    \
                        ASSERT_EQ(x, lit(-5));                          \
                }                                                       \
                ASSERT_TRUE(ADD_SAFE(&x, min, lit(0)));                 \
                ASSERT_EQ(x, min);                                      \
                ASSERT_TRUE(ADD_SAFE(&x, max, lit(0)));                 \
                ASSERT_EQ(x, max);                                      \
                if (IS_SIGNED_INTEGER_TYPE(type))                       \
                        ASSERT_FALSE(ADD_SAFE(&x, min, lit(-1)));       \
                ASSERT_FALSE(ADD_SAFE(&x, max, lit(1)));                \
                                                                        \
                x = lit(5);                                             \
                ASSERT_TRUE(INC_SAFE(&x, lit(10)));                     \
                ASSERT_EQ(x, lit(15));                                  \
                if (IS_SIGNED_INTEGER_TYPE(type)) {                     \
                        ASSERT_TRUE(INC_SAFE(&x, lit(-20)));            \
                        ASSERT_EQ(x, lit(-5));                          \
                }                                                       \
                x = min;                                                \
                ASSERT_TRUE(INC_SAFE(&x, lit(0)));                      \
                ASSERT_EQ(x, min);                                      \
                if (IS_SIGNED_INTEGER_TYPE(type))                       \
                        ASSERT_FALSE(INC_SAFE(&x, lit(-1)));            \
                x = max;                                                \
                ASSERT_TRUE(INC_SAFE(&x, lit(0)));                      \
                ASSERT_EQ(x, max);                                      \
                ASSERT_FALSE(INC_SAFE(&x, lit(1)));                     \
                                                                        \
                ASSERT_TRUE(SUB_SAFE(&x, lit(10), lit(5)));             \
                ASSERT_EQ(x, lit(5));                                   \
                if (IS_SIGNED_INTEGER_TYPE(type)) {                     \
                        ASSERT_TRUE(SUB_SAFE(&x, lit(5), lit(10)));     \
                        ASSERT_EQ(x, lit(-5));                          \
                                                                        \
                        ASSERT_TRUE(SUB_SAFE(&x, lit(5), lit(-10)));    \
                        ASSERT_EQ(x, lit(15));                          \
                } else                                                  \
                        ASSERT_FALSE(SUB_SAFE(&x, lit(5), lit(10)));    \
                ASSERT_TRUE(SUB_SAFE(&x, min, lit(0)));                 \
                ASSERT_EQ(x, min);                                      \
                ASSERT_TRUE(SUB_SAFE(&x, max, lit(0)));                 \
                ASSERT_EQ(x, max);                                      \
                ASSERT_FALSE(SUB_SAFE(&x, min, lit(1)));                \
                if (IS_SIGNED_INTEGER_TYPE(type))                       \
                        ASSERT_FALSE(SUB_SAFE(&x, max, lit(-1)));       \
                                                                        \
                x = lit(10);                                            \
                ASSERT_TRUE(DEC_SAFE(&x, lit(5)));                      \
                ASSERT_EQ(x, lit(5));                                   \
                if (IS_SIGNED_INTEGER_TYPE(type)) {                     \
                        ASSERT_TRUE(DEC_SAFE(&x, lit(10)));             \
                        ASSERT_EQ(x, lit(-5));                          \
                                                                        \
                        x = lit(5);                                     \
                        ASSERT_TRUE(DEC_SAFE(&x, lit(-10)));            \
                        ASSERT_EQ(x, lit(15));                          \
                } else                                                  \
                        ASSERT_FALSE(DEC_SAFE(&x, lit(10)));            \
                x = min;                                                \
                ASSERT_TRUE(DEC_SAFE(&x, lit(0)));                      \
                ASSERT_EQ(x, min);                                      \
                ASSERT_FALSE(DEC_SAFE(&x, lit(1)));                     \
                x = max;                                                \
                ASSERT_TRUE(DEC_SAFE(&x, lit(0)));                      \
                if (IS_SIGNED_INTEGER_TYPE(type))                       \
                        ASSERT_FALSE(DEC_SAFE(&x, lit(-1)));            \
                                                                        \
                ASSERT_TRUE(MUL_SAFE(&x, lit(2), lit(4)));              \
                ASSERT_EQ(x, lit(8));                                   \
                if (IS_SIGNED_INTEGER_TYPE(type)) {                     \
                        ASSERT_TRUE(MUL_SAFE(&x, lit(2), lit(-4)));     \
                        ASSERT_EQ(x, lit(-8));                          \
                }                                                       \
                ASSERT_TRUE(MUL_SAFE(&x, lit(5), lit(0)));              \
                ASSERT_EQ(x, lit(0));                                   \
                ASSERT_TRUE(MUL_SAFE(&x, min, lit(1)));                 \
                ASSERT_EQ(x, min);                                      \
                if (IS_SIGNED_INTEGER_TYPE(type))                       \
                        ASSERT_FALSE(MUL_SAFE(&x, min, lit(2)));        \
                ASSERT_TRUE(MUL_SAFE(&x, max, lit(1)));                 \
                ASSERT_EQ(x, max);                                      \
                ASSERT_FALSE(MUL_SAFE(&x, max, lit(2)));                \
                                                                        \
                x = lit(2);                                             \
                ASSERT_TRUE(MUL_ASSIGN_SAFE(&x, lit(4)));               \
                ASSERT_EQ(x, lit(8));                                   \
                if (IS_SIGNED_INTEGER_TYPE(type)) {                     \
                        ASSERT_TRUE(MUL_ASSIGN_SAFE(&x, lit(-1)));      \
                        ASSERT_EQ(x, lit(-8));                          \
                }                                                       \
                ASSERT_TRUE(MUL_ASSIGN_SAFE(&x, lit(0)));               \
                ASSERT_EQ(x, lit(0));                                   \
                x = min;                                                \
                ASSERT_TRUE(MUL_ASSIGN_SAFE(&x, lit(1)));               \
                ASSERT_EQ(x, min);                                      \
                if IS_SIGNED_INTEGER_TYPE(type)                         \
                        ASSERT_FALSE(MUL_ASSIGN_SAFE(&x, lit(2)));      \
                x = max;                                                \
                ASSERT_TRUE(MUL_ASSIGN_SAFE(&x, lit(1)));               \
                ASSERT_EQ(x, max);                                      \
                ASSERT_FALSE(MUL_ASSIGN_SAFE(&x, lit(2)));              \
        })

TEST(overflow_safe_math) {
        int64_t i;
        uint64_t u, *p;

        /* basic tests */
        TEST_OVERFLOW_MATH_BY_TYPE(int8_t, INT8_MIN, INT8_MAX, INT8_C);
        TEST_OVERFLOW_MATH_BY_TYPE(int16_t, INT16_MIN, INT16_MAX, INT16_C);
        TEST_OVERFLOW_MATH_BY_TYPE(int32_t, INT32_MIN, INT32_MAX, INT32_C);
        TEST_OVERFLOW_MATH_BY_TYPE(int64_t, INT64_MIN, INT64_MAX, INT64_C);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits" /* Otherwise the compiler complains about comparisons to negative numbers always being false */
        TEST_OVERFLOW_MATH_BY_TYPE(uint8_t, UINT8_C(0), UINT8_MAX, UINT8_C);
        TEST_OVERFLOW_MATH_BY_TYPE(uint16_t, UINT16_C(0), UINT16_MAX, UINT16_C);
        TEST_OVERFLOW_MATH_BY_TYPE(uint32_t, UINT32_C(0), UINT32_MAX, UINT32_C);
        TEST_OVERFLOW_MATH_BY_TYPE(uint64_t, UINT64_C(0), UINT64_MAX, UINT64_C);
#pragma GCC diagnostic pop

        /* make sure we handle pointers correctly */
        p = &u;
        ASSERT_TRUE(ADD_SAFE(p, 35, 15));
        ASSERT_EQ(u, 50U);
        ASSERT_TRUE(SUB_SAFE(p, 35, 15));
        ASSERT_EQ(u, 20U);
        ASSERT_TRUE(MUL_SAFE(p, 5, 10));
        ASSERT_EQ(u, 50U);
        ASSERT_TRUE(INC_SAFE(p, 10));
        ASSERT_EQ(u, 60U);
        ASSERT_TRUE(DEC_SAFE(p, 10));
        ASSERT_EQ(u, 50U);
        ASSERT_TRUE(MUL_ASSIGN_SAFE(p, 3));
        ASSERT_EQ(u, 150U);
        ASSERT_FALSE(ADD_SAFE(p, UINT64_MAX, 1));
        ASSERT_FALSE(SUB_SAFE(p, 0, 1));

        /* cross-type sanity checks */
        ASSERT_TRUE(ADD_SAFE(&i, INT32_MAX, 1));
        ASSERT_TRUE(SUB_SAFE(&i, INT32_MIN, 1));
        ASSERT_FALSE(ADD_SAFE(&i, UINT64_MAX, 0));
        ASSERT_TRUE(ADD_SAFE(&u, INT32_MAX, 1));
        ASSERT_TRUE(MUL_SAFE(&u, INT32_MAX, 2));
}

TEST(DIV_ROUND_UP) {
        int div;

        /* basic tests */
        ASSERT_EQ(DIV_ROUND_UP(0, 8), 0);
        ASSERT_EQ(DIV_ROUND_UP(1, 8), 1);
        ASSERT_EQ(DIV_ROUND_UP(8, 8), 1);
        ASSERT_EQ(DIV_ROUND_UP(12, 8), 2);
        ASSERT_EQ(DIV_ROUND_UP(16, 8), 2);

        /* test multiple evaluation */
        div = 0;
        ASSERT_EQ(DIV_ROUND_UP(div++, 8), 0);
        ASSERT_EQ(div, 1);
        ASSERT_EQ(DIV_ROUND_UP(++div, 8), 1);
        ASSERT_EQ(div, 2);
        ASSERT_EQ(DIV_ROUND_UP(8, div++), 4);
        ASSERT_EQ(div, 3);
        ASSERT_EQ(DIV_ROUND_UP(8, ++div), 2);
        ASSERT_EQ(div, 4);

        /* overflow test with exact division */
        ASSERT_EQ(sizeof(0U), 4U);
        ASSERT_EQ(0xfffffffaU % 10U, 0U);
        ASSERT_EQ(0xfffffffaU / 10U, 429496729U);
        ASSERT_EQ(DIV_ROUND_UP(0xfffffffaU, 10U), 429496729U);
        ASSERT_EQ((0xfffffffaU + 10U - 1U) / 10U, 0U);
        ASSERT_EQ(0xfffffffaU / 10U + !!(0xfffffffaU % 10U), 429496729U);

        /* overflow test with rounded division */
        ASSERT_EQ(0xfffffffdU % 10U, 3U);
        ASSERT_EQ(0xfffffffdU / 10U, 429496729U);
        ASSERT_EQ(DIV_ROUND_UP(0xfffffffdU, 10U), 429496730U);
        ASSERT_EQ((0xfffffffdU + 10U - 1U) / 10U, 0U);
        ASSERT_EQ(0xfffffffdU / 10U + !!(0xfffffffdU % 10U), 429496730U);
}

TEST(PTR_TO_INT) {
        /* Primary reason to have this test is to validate that pointers are large enough to hold entire int range */
        ASSERT_EQ(PTR_TO_INT(INT_TO_PTR(0)), 0);
        ASSERT_EQ(PTR_TO_INT(INT_TO_PTR(1)), 1);
        ASSERT_EQ(PTR_TO_INT(INT_TO_PTR(-1)), -1);
        ASSERT_EQ(PTR_TO_INT(INT_TO_PTR(INT_MAX)), INT_MAX);
        ASSERT_EQ(PTR_TO_INT(INT_TO_PTR(INT_MIN)), INT_MIN);
}

TEST(IN_SET) {
        ASSERT_TRUE(IN_SET(1, 1, 2));
        ASSERT_TRUE(IN_SET(1, 1, 2, 3, 4));
        ASSERT_TRUE(IN_SET(2, 1, 2, 3, 4));
        ASSERT_TRUE(IN_SET(3, 1, 2, 3, 4));
        ASSERT_TRUE(IN_SET(4, 1, 2, 3, 4));
        ASSERT_FALSE(IN_SET(0, 1, 2));
        ASSERT_FALSE(IN_SET(0, 1, 2, 3, 4));

        struct {
                unsigned x:3;
        } t = { 1 };

        ASSERT_TRUE(IN_SET(t.x, 1, 2));
        ASSERT_TRUE(IN_SET(t.x, 1, 2, 3, 4));
        ASSERT_TRUE(IN_SET(t.x, 2, 3, 4, 1));
        ASSERT_FALSE(IN_SET(t.x, 0, 2));
        ASSERT_FALSE(IN_SET(t.x, 2, 3, 4));
}

TEST(FOREACH_ARGUMENT) {
        size_t i;

        i = 0;
        uint8_t u8, u8_1 = 1, u8_2 = 2, u8_3 = 3;
        FOREACH_ARGUMENT(u8, u8_2, 8, 0xff, u8_1, u8_3, 0, 1) {
                switch (i++) {
                case 0: ASSERT_EQ(u8, u8_2); break;
                case 1: ASSERT_EQ(u8, 8U); break;
                case 2: ASSERT_EQ(u8, 0xffU); break;
                case 3: ASSERT_EQ(u8, u8_1); break;
                case 4: ASSERT_EQ(u8, u8_3); break;
                case 5: ASSERT_EQ(u8, 0U); break;
                case 6: ASSERT_EQ(u8, 1U); break;
                default: assert_not_reached();
                }
        }
        ASSERT_EQ(i, 7U);
        i = 0;
        FOREACH_ARGUMENT(u8, 0) {
                ASSERT_EQ(u8, 0U);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        i = 0;
        FOREACH_ARGUMENT(u8, 0xff) {
                ASSERT_EQ(u8, 0xffU);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        FOREACH_ARGUMENT(u8)
                assert_not_reached();

        i = 0;
        uint32_t u32, u32_1 = 0xffff0000, u32_2 = 10, u32_3 = 0xffff;
        FOREACH_ARGUMENT(u32, 1, 100, u32_2, 1000, u32_3, u32_1, 1, 0) {
                switch (i++) {
                case 0: ASSERT_EQ(u32, 1U); break;
                case 1: ASSERT_EQ(u32, 100U); break;
                case 2: ASSERT_EQ(u32, u32_2); break;
                case 3: ASSERT_EQ(u32, 1000U); break;
                case 4: ASSERT_EQ(u32, u32_3); break;
                case 5: ASSERT_EQ(u32, u32_1); break;
                case 6: ASSERT_EQ(u32, 1U); break;
                case 7: ASSERT_EQ(u32, 0U); break;
                default: assert_not_reached();
                }
        }
        ASSERT_EQ(i, 8U);
        i = 0;
        FOREACH_ARGUMENT(u32, 0) {
                ASSERT_EQ(u32, 0U);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        i = 0;
        FOREACH_ARGUMENT(u32, 1000) {
                ASSERT_EQ(u32, 1000U);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        FOREACH_ARGUMENT(u32)
                assert_not_reached();

        i = 0;
        uint64_t u64, u64_1 = 0xffffffffffffffff, u64_2 = 50, u64_3 = 0xffff;
        FOREACH_ARGUMENT(u64, 44, 0, u64_3, 100, u64_2, u64_1, 50000) {
                switch (i++) {
                case 0: ASSERT_EQ(u64, 44U); break;
                case 1: ASSERT_EQ(u64, 0U); break;
                case 2: ASSERT_EQ(u64, u64_3); break;
                case 3: ASSERT_EQ(u64, 100U); break;
                case 4: ASSERT_EQ(u64, u64_2); break;
                case 5: ASSERT_EQ(u64, u64_1); break;
                case 6: ASSERT_EQ(u64, 50000U); break;
                default: assert_not_reached();
                }
        }
        ASSERT_EQ(i, 7U);
        i = 0;
        FOREACH_ARGUMENT(u64, 0) {
                ASSERT_EQ(u64, 0U);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        i = 0;
        FOREACH_ARGUMENT(u64, 0xff00ff00000000) {
                ASSERT_EQ(u64, 0xff00ff00000000U);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        FOREACH_ARGUMENT(u64)
                assert_not_reached();

        struct test {
                int a;
                char b;
        };

        i = 0;
        struct test s,
                s_1 = { .a = 0, .b = 'c', },
                s_2 = { .a = 100000, .b = 'z', },
                s_3 = { .a = 0xff, .b = 'q', },
                s_4 = { .a = 1, .b = 'x', };
        FOREACH_ARGUMENT(s, s_1, (struct test){ .a = 10, .b = 'd', }, s_2, (struct test){}, s_3, s_4) {
                switch (i++) {
                case 0: ASSERT_EQ(s.a, 0); ASSERT_EQ(s.b, 'c'); break;
                case 1: ASSERT_EQ(s.a, 10); ASSERT_EQ(s.b, 'd'); break;
                case 2: ASSERT_EQ(s.a, 100000); ASSERT_EQ(s.b, 'z'); break;
                case 3: ASSERT_EQ(s.a, 0); ASSERT_EQ(s.b, 0); break;
                case 4: ASSERT_EQ(s.a, 0xff); ASSERT_EQ(s.b, 'q'); break;
                case 5: ASSERT_EQ(s.a, 1); ASSERT_EQ(s.b, 'x'); break;
                default: assert_not_reached();
                }
        }
        ASSERT_EQ(i, 6U);
        i = 0;
        FOREACH_ARGUMENT(s, (struct test){ .a = 1, .b = 'A', }) {
                ASSERT_EQ(s.a, 1);
                ASSERT_EQ(s.b, 'A');
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        FOREACH_ARGUMENT(s)
                assert_not_reached();

        i = 0;
        struct test *p, *p_1 = &s_1, *p_2 = &s_2, *p_3 = &s_3, *p_4 = &s_4;
        FOREACH_ARGUMENT(p, p_1, NULL, p_2, p_3, NULL, p_4, NULL) {
                switch (i++) {
                case 0: ASSERT_PTR_EQ(p, p_1); break;
                case 1: ASSERT_NULL(p); break;
                case 2: ASSERT_PTR_EQ(p, p_2); break;
                case 3: ASSERT_PTR_EQ(p, p_3); break;
                case 4: ASSERT_NULL(p); break;
                case 5: ASSERT_PTR_EQ(p, p_4); break;
                case 6: ASSERT_NULL(p); break;
                default: assert_not_reached();
                }
        }
        ASSERT_EQ(i, 7U);
        i = 0;
        FOREACH_ARGUMENT(p, p_3) {
                ASSERT_PTR_EQ(p, p_3);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        FOREACH_ARGUMENT(p)
                assert_not_reached();

        i = 0;
        void *v, *v_1 = p_1, *v_2 = p_2, *v_3 = p_3;
        uint32_t *u32p = &u32;
        FOREACH_ARGUMENT(v, v_1, NULL, u32p, v_3, p_2, p_4, v_2, NULL) {
                switch (i++) {
                case 0: ASSERT_PTR_EQ(v, v_1); break;
                case 1: ASSERT_NULL(v); break;
                case 2: ASSERT_PTR_EQ(v, u32p); break;
                case 3: ASSERT_PTR_EQ(v, v_3); break;
                case 4: ASSERT_PTR_EQ(v, p_2); break;
                case 5: ASSERT_PTR_EQ(v, p_4); break;
                case 6: ASSERT_PTR_EQ(v, v_2); break;
                case 7: ASSERT_NULL(v); break;
                default: assert_not_reached();
                }
        }
        ASSERT_EQ(i, 8U);
        i = 0;
        FOREACH_ARGUMENT(v, NULL) {
                ASSERT_NULL(v);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        i = 0;
        FOREACH_ARGUMENT(v, v_1) {
                ASSERT_PTR_EQ(v, v_1);
                ASSERT_EQ(i++, 0U);
        }
        ASSERT_EQ(i, 1U);
        FOREACH_ARGUMENT(v)
                assert_not_reached();
}

TEST(ALIGN_TO) {
        ASSERT_EQ(ALIGN_TO(0, 1), 0U);
        ASSERT_EQ(ALIGN_TO(1, 1), 1U);
        ASSERT_EQ(ALIGN_TO(2, 1), 2U);
        ASSERT_EQ(ALIGN_TO(3, 1), 3U);
        ASSERT_EQ(ALIGN_TO(4, 1), 4U);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX-1, 1), SIZE_MAX-1);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX, 1), SIZE_MAX);

        ASSERT_EQ(ALIGN_TO(0, 2), 0U);
        ASSERT_EQ(ALIGN_TO(1, 2), 2U);
        ASSERT_EQ(ALIGN_TO(2, 2), 2U);
        ASSERT_EQ(ALIGN_TO(3, 2), 4U);
        ASSERT_EQ(ALIGN_TO(4, 2), 4U);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX-3, 2), SIZE_MAX-3);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX-2, 2), SIZE_MAX-1);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX-1, 2), SIZE_MAX-1);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX, 2), SIZE_MAX); /* overflow */

        ASSERT_EQ(ALIGN_TO(0, 4), 0U);
        ASSERT_EQ(ALIGN_TO(1, 4), 4U);
        ASSERT_EQ(ALIGN_TO(2, 4), 4U);
        ASSERT_EQ(ALIGN_TO(3, 4), 4U);
        ASSERT_EQ(ALIGN_TO(4, 4), 4U);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX-3, 4), SIZE_MAX-3);
        ASSERT_EQ(ALIGN_TO(SIZE_MAX-2, 4), SIZE_MAX); /* overflow */
        ASSERT_EQ(ALIGN_TO(SIZE_MAX-1, 4), SIZE_MAX); /* overflow */
        ASSERT_EQ(ALIGN_TO(SIZE_MAX, 4), SIZE_MAX);   /* overflow */

        ASSERT_EQ(ALIGN_TO_U64(0, 1), 0U);
        ASSERT_EQ(ALIGN_TO_U64(1, 1), 1U);
        ASSERT_EQ(ALIGN_TO_U64(2, 1), 2U);
        ASSERT_EQ(ALIGN_TO_U64(3, 1), 3U);
        ASSERT_EQ(ALIGN_TO_U64(4, 1), 4U);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX-1, 1), UINT64_MAX-1);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX, 1), UINT64_MAX);

        ASSERT_EQ(ALIGN_TO_U64(0, 2), 0U);
        ASSERT_EQ(ALIGN_TO_U64(1, 2), 2U);
        ASSERT_EQ(ALIGN_TO_U64(2, 2), 2U);
        ASSERT_EQ(ALIGN_TO_U64(3, 2), 4U);
        ASSERT_EQ(ALIGN_TO_U64(4, 2), 4U);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX-3, 2), UINT64_MAX-3);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX-2, 2), UINT64_MAX-1);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX-1, 2), UINT64_MAX-1);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX, 2), UINT64_MAX); /* overflow */

        ASSERT_EQ(ALIGN_TO_U64(0, 4), 0U);
        ASSERT_EQ(ALIGN_TO_U64(1, 4), 4U);
        ASSERT_EQ(ALIGN_TO_U64(2, 4), 4U);
        ASSERT_EQ(ALIGN_TO_U64(3, 4), 4U);
        ASSERT_EQ(ALIGN_TO_U64(4, 4), 4U);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX-3, 4), UINT64_MAX-3);
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX-2, 4), UINT64_MAX); /* overflow */
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX-1, 4), UINT64_MAX); /* overflow */
        ASSERT_EQ(ALIGN_TO_U64(UINT64_MAX, 4), UINT64_MAX);   /* overflow */

        assert_cc(CONST_ALIGN_TO(96, 512) == 512);
        assert_cc(CONST_ALIGN_TO(511, 512) == 512);
        assert_cc(CONST_ALIGN_TO(512, 512) == 512);
        assert_cc(CONST_ALIGN_TO(513, 512) == 1024);
        assert_cc(CONST_ALIGN_TO(sizeof(int), 64) == 64);

        assert_cc(__builtin_types_compatible_p(typeof(CONST_ALIGN_TO(4, 3)), typeof(VOID_0)));
        assert_cc(__builtin_types_compatible_p(typeof(CONST_ALIGN_TO(SIZE_MAX, 512)), typeof(VOID_0)));
}

TEST(align_down) {
        ASSERT_EQ(ALIGN_DOWN(0, 1), 0U);
        ASSERT_EQ(ALIGN_DOWN(1, 1), 1U);
        ASSERT_EQ(ALIGN_DOWN(2, 1), 2U);
        ASSERT_EQ(ALIGN_DOWN(3, 1), 3U);
        ASSERT_EQ(ALIGN_DOWN(4, 1), 4U);
        ASSERT_EQ(ALIGN_DOWN(SIZE_MAX-1, 1), SIZE_MAX-1);
        ASSERT_EQ(ALIGN_DOWN(SIZE_MAX, 1), SIZE_MAX);

        ASSERT_EQ(ALIGN_DOWN(0, 2), 0U);
        ASSERT_EQ(ALIGN_DOWN(1, 2), 0U);
        ASSERT_EQ(ALIGN_DOWN(2, 2), 2U);
        ASSERT_EQ(ALIGN_DOWN(3, 2), 2U);
        ASSERT_EQ(ALIGN_DOWN(4, 2), 4U);
        ASSERT_EQ(ALIGN_DOWN(SIZE_MAX-1, 2), SIZE_MAX-1);
        ASSERT_EQ(ALIGN_DOWN(SIZE_MAX, 2), SIZE_MAX-1);

        ASSERT_EQ(ALIGN_DOWN(0, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN(1, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN(2, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN(3, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN(4, 4), 4U);
        ASSERT_EQ(ALIGN_DOWN(SIZE_MAX-1, 4), SIZE_MAX-3);
        ASSERT_EQ(ALIGN_DOWN(SIZE_MAX, 4), SIZE_MAX-3);

        ASSERT_EQ(ALIGN_DOWN_U64(0, 1), 0U);
        ASSERT_EQ(ALIGN_DOWN_U64(1, 1), 1U);
        ASSERT_EQ(ALIGN_DOWN_U64(2, 1), 2U);
        ASSERT_EQ(ALIGN_DOWN_U64(3, 1), 3U);
        ASSERT_EQ(ALIGN_DOWN_U64(4, 1), 4U);
        ASSERT_EQ(ALIGN_DOWN_U64(UINT64_MAX-1, 1), UINT64_MAX-1);
        ASSERT_EQ(ALIGN_DOWN_U64(UINT64_MAX, 1), UINT64_MAX);

        ASSERT_EQ(ALIGN_DOWN_U64(0, 2), 0U);
        ASSERT_EQ(ALIGN_DOWN_U64(1, 2), 0U);
        ASSERT_EQ(ALIGN_DOWN_U64(2, 2), 2U);
        ASSERT_EQ(ALIGN_DOWN_U64(3, 2), 2U);
        ASSERT_EQ(ALIGN_DOWN_U64(4, 2), 4U);
        ASSERT_EQ(ALIGN_DOWN_U64(UINT64_MAX-1, 2), UINT64_MAX-1);
        ASSERT_EQ(ALIGN_DOWN_U64(UINT64_MAX, 2), UINT64_MAX-1);

        ASSERT_EQ(ALIGN_DOWN_U64(0, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN_U64(1, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN_U64(2, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN_U64(3, 4), 0U);
        ASSERT_EQ(ALIGN_DOWN_U64(4, 4), 4U);
        ASSERT_EQ(ALIGN_DOWN_U64(UINT64_MAX-1, 4), UINT64_MAX-3);
        ASSERT_EQ(ALIGN_DOWN_U64(UINT64_MAX, 4), UINT64_MAX-3);
}

TEST(align_offset) {
        ASSERT_EQ(ALIGN_OFFSET(0, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET(1, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET(2, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET(3, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET(4, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET(SIZE_MAX-1, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET(SIZE_MAX, 1), 0U);

        ASSERT_EQ(ALIGN_OFFSET(0, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET(1, 2), 1U);
        ASSERT_EQ(ALIGN_OFFSET(2, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET(3, 2), 1U);
        ASSERT_EQ(ALIGN_OFFSET(4, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET(SIZE_MAX-1, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET(SIZE_MAX, 2), 1U);

        ASSERT_EQ(ALIGN_OFFSET(0, 4), 0U);
        ASSERT_EQ(ALIGN_OFFSET(1, 4), 1U);
        ASSERT_EQ(ALIGN_OFFSET(2, 4), 2U);
        ASSERT_EQ(ALIGN_OFFSET(3, 4), 3U);
        ASSERT_EQ(ALIGN_OFFSET(4, 4), 0U);
        ASSERT_EQ(ALIGN_OFFSET(SIZE_MAX-1, 4), 2U);
        ASSERT_EQ(ALIGN_OFFSET(SIZE_MAX, 4), 3U);

        ASSERT_EQ(ALIGN_OFFSET_U64(0, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(1, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(2, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(3, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(4, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(UINT64_MAX-1, 1), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(UINT64_MAX, 1), 0U);

        ASSERT_EQ(ALIGN_OFFSET_U64(0, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(1, 2), 1U);
        ASSERT_EQ(ALIGN_OFFSET_U64(2, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(3, 2), 1U);
        ASSERT_EQ(ALIGN_OFFSET_U64(4, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(UINT64_MAX-1, 2), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(UINT64_MAX, 2), 1U);

        ASSERT_EQ(ALIGN_OFFSET_U64(0, 4), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(1, 4), 1U);
        ASSERT_EQ(ALIGN_OFFSET_U64(2, 4), 2U);
        ASSERT_EQ(ALIGN_OFFSET_U64(3, 4), 3U);
        ASSERT_EQ(ALIGN_OFFSET_U64(4, 4), 0U);
        ASSERT_EQ(ALIGN_OFFSET_U64(UINT64_MAX-1, 4), 2U);
        ASSERT_EQ(ALIGN_OFFSET_U64(UINT64_MAX, 4), 3U);
}

TEST(flags) {
        enum {
                F1 = 1 << 0,
                F2 = 1 << 1,
                F3 = 1 << 2,
                F_ALL = F1 | F2 | F3
        };
        unsigned n, f;

        ASSERT_TRUE(FLAGS_SET(0, 0));
        ASSERT_TRUE(FLAGS_SET(F1, F1));
        ASSERT_TRUE(FLAGS_SET(F1 | F2, F1));
        ASSERT_TRUE(FLAGS_SET(F1 | F3, F1 | F3));
        ASSERT_TRUE(FLAGS_SET(F1 | F2 | F3, F_ALL));
        ASSERT_FALSE(FLAGS_SET(0, F1));
        ASSERT_FALSE(FLAGS_SET(F2, F1));
        ASSERT_FALSE(FLAGS_SET(F1 | F2, F3));
        ASSERT_FALSE(FLAGS_SET(F1 | F2, F1 | F3));
        ASSERT_FALSE(FLAGS_SET(F1 | F2 | F3, ~F_ALL));

        /* Check for no double eval. */
        n = F2;
        f = F1;
        ASSERT_FALSE(FLAGS_SET(--n, ++f));
        ASSERT_EQ(n, (unsigned) (F1));
        ASSERT_EQ(f, (unsigned) (F2));

        SET_FLAG(n, F3, true);
        ASSERT_EQ(n, (unsigned) (F1 | F3));
        SET_FLAG(n, F2, false);
        ASSERT_EQ(n, (unsigned) (F1 | F3));
        SET_FLAG(n, F3, false);
        ASSERT_EQ(n, (unsigned) (F1));
        SET_FLAG(n, F1, true);
        ASSERT_EQ(n, (unsigned) (F1));
        SET_FLAG(n, F1 | F3, true);
        ASSERT_EQ(n, (unsigned) (F1 | F3));
        SET_FLAG(n, F_ALL, false);
        ASSERT_EQ(n, 0U);

        ASSERT_EQ(UPDATE_FLAG(0, 0, true), 0);
        ASSERT_EQ(UPDATE_FLAG(0, F1, true), F1);
        ASSERT_EQ(UPDATE_FLAG(0, F1 | F2, true), F1 | F2);
        ASSERT_EQ(UPDATE_FLAG(F1, 0, true), F1);
        ASSERT_EQ(UPDATE_FLAG(F1, F1, true), F1);
        ASSERT_EQ(UPDATE_FLAG(F1, F3, true), F1 | F3);
        ASSERT_EQ(UPDATE_FLAG(F1, F1 | F3, true), F1 | F3);
        ASSERT_EQ(UPDATE_FLAG(F1, F_ALL, true), F_ALL);
        ASSERT_EQ(UPDATE_FLAG(0, 0, false), 0);
        ASSERT_EQ(UPDATE_FLAG(0, F1, false), 0);
        ASSERT_EQ(UPDATE_FLAG(0, F1 | F2, false), 0);
        ASSERT_EQ(UPDATE_FLAG(F1, 0, false), F1);
        ASSERT_EQ(UPDATE_FLAG(F1, F1, false), 0);
        ASSERT_EQ(UPDATE_FLAG(F1, F3, false), F1);
        ASSERT_EQ(UPDATE_FLAG(F1, F1 | F3, false), 0);
        ASSERT_EQ(UPDATE_FLAG(F1, F2 | F3, false), F1);
        ASSERT_EQ(UPDATE_FLAG(F1, F_ALL, false), 0);
        ASSERT_EQ(UPDATE_FLAG(F_ALL, F_ALL, false), 0);

        /* Check for no double eval. */
        n = F2;
        f = F1;
        ASSERT_EQ(UPDATE_FLAG(--n, ++f, true), (unsigned) (F1 | F2));
        ASSERT_EQ(n, (unsigned) (F1));
        ASSERT_EQ(f, (unsigned) (F2));
}

TEST(DECIMAL_STR_WIDTH) {
        ASSERT_EQ(DECIMAL_STR_WIDTH(0), 1U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(1), 1U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(2), 1U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(9), 1U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(10), 2U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(11), 2U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(99), 2U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(100), 3U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(101), 3U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-1), 2U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-2), 2U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-9), 2U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-10), 3U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-11), 3U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-99), 3U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-100), 4U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(-101), 4U);
        ASSERT_EQ(DECIMAL_STR_WIDTH(UINT64_MAX), STRLEN("18446744073709551615"));
        ASSERT_EQ(DECIMAL_STR_WIDTH(INT64_MAX), STRLEN("9223372036854775807"));
        ASSERT_EQ(DECIMAL_STR_WIDTH(INT64_MIN), STRLEN("-9223372036854775808"));
}

TEST(DECIMAL_STR_MAX) {
        int8_t s8_longest = INT8_MIN;
        int16_t s16_longest = INT16_MIN;
        int32_t s32_longest = INT32_MIN;
        int64_t s64_longest = INT64_MIN;
        uint8_t u8_longest = UINT8_MAX;
        uint16_t u16_longest = UINT16_MAX;
        uint32_t u32_longest = UINT32_MAX;
        uint64_t u64_longest = UINT64_MAX;

        /* NB: Always add +1, because DECIMAL_STR_MAX() includes space for trailing NUL byte, but
         * DECIMAL_STR_WIDTH() does not! */
        ASSERT_EQ(DECIMAL_STR_MAX(int8_t), DECIMAL_STR_WIDTH(s8_longest)+1);
        ASSERT_EQ(DECIMAL_STR_MAX(int16_t), DECIMAL_STR_WIDTH(s16_longest)+1);
        ASSERT_EQ(DECIMAL_STR_MAX(int32_t), DECIMAL_STR_WIDTH(s32_longest)+1);
        ASSERT_EQ(DECIMAL_STR_MAX(int64_t), DECIMAL_STR_WIDTH(s64_longest)+1);

        ASSERT_EQ(DECIMAL_STR_MAX(uint8_t), DECIMAL_STR_WIDTH(u8_longest)+1);
        ASSERT_EQ(DECIMAL_STR_MAX(uint16_t), DECIMAL_STR_WIDTH(u16_longest)+1);
        ASSERT_EQ(DECIMAL_STR_MAX(uint32_t), DECIMAL_STR_WIDTH(u32_longest)+1);
        ASSERT_EQ(DECIMAL_STR_MAX(uint64_t), DECIMAL_STR_WIDTH(u64_longest)+1);
}

TEST(PTR_SUB1) {
        static const uint64_t x[4] = { 2, 3, 4, 5 };
        const uint64_t *p;

        p = x + ELEMENTSOF(x)-1;
        ASSERT_EQ(*p, 5U);

        p = PTR_SUB1(p, x);
        ASSERT_EQ(*p, 4U);

        p = PTR_SUB1(p, x);
        ASSERT_EQ(*p, 3U);

        p = PTR_SUB1(p, x);
        ASSERT_EQ(*p, 2U);

        p = PTR_SUB1(p, x);
        ASSERT_NULL(p);

        p = PTR_SUB1(p, x);
        ASSERT_NULL(p);
}

TEST(ISPOWEROF2) {
        uint64_t u;
        int64_t i;

        /* First, test constant expressions */
        ASSERT_FALSE(ISPOWEROF2(-2));
        ASSERT_FALSE(ISPOWEROF2(-1));
        ASSERT_FALSE(ISPOWEROF2(0));
        ASSERT_TRUE(ISPOWEROF2(1));
        ASSERT_TRUE(ISPOWEROF2(2));
        ASSERT_FALSE(ISPOWEROF2(3));
        ASSERT_TRUE(ISPOWEROF2(4));
        ASSERT_FALSE(ISPOWEROF2(5));
        ASSERT_FALSE(ISPOWEROF2(6));
        ASSERT_FALSE(ISPOWEROF2(7));
        ASSERT_TRUE(ISPOWEROF2(8));
        ASSERT_FALSE(ISPOWEROF2(9));
        ASSERT_FALSE(ISPOWEROF2(1022));
        ASSERT_TRUE(ISPOWEROF2(1024));
        ASSERT_FALSE(ISPOWEROF2(1025));
        ASSERT_FALSE(ISPOWEROF2(UINT64_C(0xffffffff)));
        ASSERT_TRUE(ISPOWEROF2(UINT64_C(0x100000000)));
        ASSERT_FALSE(ISPOWEROF2(UINT64_C(0x100000001)));

        /* Then, test dynamic expressions, and if they are side-effect free */
        i = -2;
        ASSERT_FALSE(ISPOWEROF2(i++));
        ASSERT_EQ(i, -1);
        ASSERT_FALSE(ISPOWEROF2(i++));
        ASSERT_EQ(i, 0);
        ASSERT_FALSE(ISPOWEROF2(i++));
        ASSERT_EQ(i, 1);
        ASSERT_TRUE(ISPOWEROF2(i++));
        ASSERT_EQ(i, 2);
        ASSERT_TRUE(ISPOWEROF2(i++));
        ASSERT_EQ(i, 3);
        ASSERT_FALSE(ISPOWEROF2(i++));
        ASSERT_EQ(i, 4);
        ASSERT_TRUE(ISPOWEROF2(i++));
        ASSERT_EQ(i, 5);
        ASSERT_FALSE(ISPOWEROF2(i));

        u = 0;
        ASSERT_FALSE(ISPOWEROF2(u++));
        ASSERT_EQ(u, 1U);
        ASSERT_TRUE(ISPOWEROF2(u++));
        ASSERT_EQ(u, 2U);
        ASSERT_TRUE(ISPOWEROF2(u++));
        ASSERT_EQ(u, 3U);
        ASSERT_FALSE(ISPOWEROF2(u++));
        ASSERT_EQ(u, 4U);
        ASSERT_TRUE(ISPOWEROF2(u++));
        ASSERT_EQ(u, 5U);
        ASSERT_FALSE(ISPOWEROF2(u));
}

TEST(ALIGNED) {
        ASSERT_TRUE(IS_ALIGNED16(NULL));
        ASSERT_TRUE(IS_ALIGNED32(NULL));
        ASSERT_TRUE(IS_ALIGNED64(NULL));

        uint64_t u64;
        uint32_t u32;
        uint16_t u16;

        ASSERT_TRUE(IS_ALIGNED16(&u16));
        ASSERT_TRUE(IS_ALIGNED16(&u32));
        ASSERT_TRUE(IS_ALIGNED16(&u64));
        ASSERT_TRUE(IS_ALIGNED32(&u32));
        ASSERT_TRUE(IS_ALIGNED32(&u64));
        ASSERT_TRUE(IS_ALIGNED64(&u64));

        _align_(32) uint8_t ua256;
        _align_(8) uint8_t ua64;
        _align_(4) uint8_t ua32;
        _align_(2) uint8_t ua16;

        ASSERT_TRUE(IS_ALIGNED16(&ua256));
        ASSERT_TRUE(IS_ALIGNED32(&ua256));
        ASSERT_TRUE(IS_ALIGNED64(&ua256));

        ASSERT_TRUE(IS_ALIGNED16(&ua64));
        ASSERT_TRUE(IS_ALIGNED32(&ua64));
        ASSERT_TRUE(IS_ALIGNED64(&ua64));

        ASSERT_TRUE(IS_ALIGNED16(&ua32));
        ASSERT_TRUE(IS_ALIGNED32(&ua32));

        ASSERT_TRUE(IS_ALIGNED16(&ua16));

#ifdef __x86_64__
        /* Conditionalized on x86-64, since there we know for sure that all three types are aligned to
         * their size. Too lazy to figure it out for other archs */
        void *p = UINT_TO_PTR(1); /* definitely not aligned */
        ASSERT_FALSE(IS_ALIGNED16(p));
        ASSERT_FALSE(IS_ALIGNED32(p));
        ASSERT_FALSE(IS_ALIGNED64(p));

        ASSERT_TRUE(IS_ALIGNED16(ALIGN2_PTR(p)));
        ASSERT_TRUE(IS_ALIGNED32(ALIGN4_PTR(p)));
        ASSERT_TRUE(IS_ALIGNED64(ALIGN8_PTR(p)));

        p = UINT_TO_PTR(-1); /* also definitely not aligned */
        ASSERT_FALSE(IS_ALIGNED16(p));
        ASSERT_FALSE(IS_ALIGNED32(p));
        ASSERT_FALSE(IS_ALIGNED64(p));
#endif
}

TEST(FOREACH_ARRAY) {
        int a[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        int b[10] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
        int x, n;

        x = n = 0;
        FOREACH_ARRAY(i, a, 10) {
                x += *i;
                n++;
        }
        ASSERT_EQ(x, 45);
        ASSERT_EQ(n, 10);

        x = n = 0;
        FOREACH_ARRAY(i, a, 10)
                FOREACH_ARRAY(j, b, 10) {
                        x += (*i) * (*j);
                        n++;
                }
        ASSERT_EQ(x, 45 * 45);
        ASSERT_EQ(n, 10 * 10);

        x = n = 0;
        FOREACH_ARRAY(i, a, 5)
                FOREACH_ARRAY(j, b, 5) {
                        x += (*i) * (*j);
                        n++;
                }
        ASSERT_EQ(x, 10 * 35);
        ASSERT_EQ(n, 5 * 5);

        x = n = 0;
        FOREACH_ARRAY(i, a, 0)
                FOREACH_ARRAY(j, b, 0) {
                        x += (*i) * (*j);
                        n++;
                }
        ASSERT_EQ(x, 0);
        ASSERT_EQ(n, 0);

        x = n = 0;
        FOREACH_ARRAY(i, a, -1)
                FOREACH_ARRAY(j, b, -1) {
                        x += (*i) * (*j);
                        n++;
                }
        ASSERT_EQ(x, 0);
        ASSERT_EQ(n, 0);
}

#define TEST_ROUND_UP_BY_TYPE(type, max_value)                          \
        ({                                                              \
                type x, y;                                              \
                x = 0, y = 1;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 0);                    \
                x = 0, y = 2;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 0);                    \
                x = 0, y = 3;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 0);                    \
                x = 0, y = 4;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 0);                    \
                x = 1, y = 1;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 1);                    \
                x = 1, y = 2;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 2);                    \
                x = 1, y = 3;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 3);                    \
                x = 1, y = 4;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 4);                    \
                x = 2, y = 1;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 2);                    \
                x = 2, y = 2;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 2);                    \
                x = 2, y = 3;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 3);                    \
                x = 2, y = 4;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 4);                    \
                x = 3, y = 1;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 3);                    \
                x = 3, y = 2;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 4);                    \
                x = 3, y = 3;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 3);                    \
                x = 3, y = 4;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 4);                    \
                x = 4, y = 1;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 4);                    \
                x = 4, y = 2;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 4);                    \
                x = 4, y = 3;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 6);                    \
                x = 4, y = 4;                                           \
                ASSERT_EQ(ROUND_UP(x, y), (type) 4);                    \
                x = max_value, y = 1;                                   \
                ASSERT_EQ(ROUND_UP(x, y), max_value);                   \
                x = max_value, y = 2;                                   \
                ASSERT_EQ(ROUND_UP(x, y), max_value);                   \
                x = max_value, y = 3;                                   \
                ASSERT_EQ(ROUND_UP(x, y), max_value);                   \
                x = max_value, y = 4;                                   \
                ASSERT_EQ(ROUND_UP(x, y), max_value);                   \
                x = max_value-1, y = 1;                                 \
                ASSERT_EQ(ROUND_UP(x, y), max_value-1);                 \
                x = max_value-1, y = 2;                                 \
                ASSERT_EQ(ROUND_UP(x, y), max_value-1);                 \
                x = max_value-1, y = 4;                                 \
                ASSERT_EQ(ROUND_UP(x, y), max_value);                   \
        })

TEST(ROUND_UP) {
        TEST_ROUND_UP_BY_TYPE(uint8_t, UINT8_MAX);
        TEST_ROUND_UP_BY_TYPE(uint16_t, UINT16_MAX);
        TEST_ROUND_UP_BY_TYPE(uint32_t, UINT32_MAX);
        TEST_ROUND_UP_BY_TYPE(uint64_t, UINT64_MAX);
}

TEST(u64_multiply_safe) {
        ASSERT_EQ(u64_multiply_safe(0, 0), 0U);
        ASSERT_EQ(u64_multiply_safe(10, 0), 0U);
        ASSERT_EQ(u64_multiply_safe(0, 10), 0U);
        ASSERT_EQ(u64_multiply_safe(10, 10), 100U);

        ASSERT_EQ(u64_multiply_safe(UINT64_MAX, 0), 0U);
        ASSERT_EQ(u64_multiply_safe(UINT64_MAX, 1), UINT64_MAX);
        ASSERT_EQ(u64_multiply_safe(UINT64_MAX, 2), 0U);
        ASSERT_EQ(u64_multiply_safe(0, UINT64_MAX), 0U);
        ASSERT_EQ(u64_multiply_safe(1, UINT64_MAX), UINT64_MAX);
        ASSERT_EQ(u64_multiply_safe(2, UINT64_MAX), 0U);

        ASSERT_EQ(u64_multiply_safe(UINT64_MAX / 2, 0), 0U);
        ASSERT_EQ(u64_multiply_safe(UINT64_MAX / 2, 1), UINT64_MAX / 2);
        ASSERT_EQ(u64_multiply_safe(UINT64_MAX / 2, 2), UINT64_MAX - 1);
        ASSERT_EQ(u64_multiply_safe(UINT64_MAX / 2, 3), 0U);
        ASSERT_EQ(u64_multiply_safe(0, UINT64_MAX / 2), 0U);
        ASSERT_EQ(u64_multiply_safe(1, UINT64_MAX / 2), UINT64_MAX / 2);
        ASSERT_EQ(u64_multiply_safe(2, UINT64_MAX / 2), UINT64_MAX - 1);
        ASSERT_EQ(u64_multiply_safe(3, UINT64_MAX / 2), 0U);

        ASSERT_EQ(u64_multiply_safe(UINT64_MAX, UINT64_MAX), 0U);
}

static void test_once_impl(void) {
        static unsigned count = 0;

        if (ONCE) {
                log_info("This should be logged only once.");
                count++;
        }

        ASSERT_EQ(count, 1u);
}

TEST(once) {
        for (unsigned i = 0; i < 20; i++)
                test_once_impl();
}

DEFINE_TEST_MAIN(LOG_INFO);
