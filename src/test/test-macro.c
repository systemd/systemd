/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "log.h"
#include "macro.h"
#include "tests.h"

static void test_align_power2(void) {
        unsigned long i, p2;

        log_info("/* %s */", __func__);

        assert_se(ALIGN_POWER2(0) == 0);
        assert_se(ALIGN_POWER2(1) == 1);
        assert_se(ALIGN_POWER2(2) == 2);
        assert_se(ALIGN_POWER2(3) == 4);
        assert_se(ALIGN_POWER2(4) == 4);
        assert_se(ALIGN_POWER2(5) == 8);
        assert_se(ALIGN_POWER2(6) == 8);
        assert_se(ALIGN_POWER2(7) == 8);
        assert_se(ALIGN_POWER2(9) == 16);
        assert_se(ALIGN_POWER2(10) == 16);
        assert_se(ALIGN_POWER2(11) == 16);
        assert_se(ALIGN_POWER2(12) == 16);
        assert_se(ALIGN_POWER2(13) == 16);
        assert_se(ALIGN_POWER2(14) == 16);
        assert_se(ALIGN_POWER2(15) == 16);
        assert_se(ALIGN_POWER2(16) == 16);
        assert_se(ALIGN_POWER2(17) == 32);

        assert_se(ALIGN_POWER2(ULONG_MAX) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX - 1) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX - 1024) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX / 2) == ULONG_MAX / 2 + 1);
        assert_se(ALIGN_POWER2(ULONG_MAX + 1) == 0);

        for (i = 1; i < 131071; ++i) {
                for (p2 = 1; p2 < i; p2 <<= 1)
                        /* empty */ ;

                assert_se(ALIGN_POWER2(i) == p2);
        }

        for (i = ULONG_MAX - 1024; i < ULONG_MAX; ++i) {
                for (p2 = 1; p2 && p2 < i; p2 <<= 1)
                        /* empty */ ;

                assert_se(ALIGN_POWER2(i) == p2);
        }
}

static void test_max(void) {
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

        log_info("/* %s */", __func__);

        assert_cc(sizeof(val1.b) == sizeof(int) * 100);

        /* CONST_MAX returns (void) instead of a value if the passed arguments
         * are not of the same type or not constant expressions. */
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 10)), int));
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 1U)), void));

        assert_se(val1.a == 100);
        assert_se(MAX(++d, 0) == 1);
        assert_se(d == 1);

        assert_cc(MAXSIZE(char[3], uint16_t) == 3);
        assert_cc(MAXSIZE(char[3], uint32_t) == 4);
        assert_cc(MAXSIZE(char, long) == sizeof(long));

        assert_se(MAX(-5, 5) == 5);
        assert_se(MAX(5, 5) == 5);
        assert_se(MAX(MAX(1, MAX(2, MAX(3, 4))), 5) == 5);
        assert_se(MAX(MAX(1, MAX(2, MAX(3, 2))), 1) == 3);
        assert_se(MAX(MIN(1, MIN(2, MIN(3, 4))), 5) == 5);
        assert_se(MAX(MAX(1, MIN(2, MIN(3, 2))), 1) == 2);
        assert_se(LESS_BY(8, 4) == 4);
        assert_se(LESS_BY(8, 8) == 0);
        assert_se(LESS_BY(4, 8) == 0);
        assert_se(LESS_BY(16, LESS_BY(8, 4)) == 12);
        assert_se(LESS_BY(4, LESS_BY(8, 4)) == 0);
        assert_se(CMP(3, 5) == -1);
        assert_se(CMP(5, 3) == 1);
        assert_se(CMP(5, 5) == 0);
        assert_se(CMP(x, y) == -1);
        assert_se(CMP(y, x) == 1);
        assert_se(CMP(x, x) == 0);
        assert_se(CMP(y, y) == 0);
        assert_se(CMP(UINT64_MAX, (uint64_t) 0) == 1);
        assert_se(CMP((uint64_t) 0, UINT64_MAX) == -1);
        assert_se(CMP(UINT64_MAX, UINT64_MAX) == 0);
        assert_se(CMP(INT64_MIN, INT64_MAX) == -1);
        assert_se(CMP(INT64_MAX, INT64_MIN) == 1);
        assert_se(CMP(INT64_MAX, INT64_MAX) == 0);
        assert_se(CMP(INT64_MIN, INT64_MIN) == 0);
        assert_se(CMP(INT64_MAX, (int64_t) 0) == 1);
        assert_se(CMP((int64_t) 0, INT64_MIN) == 1);
        assert_se(CMP(INT64_MIN, (int64_t) 0) == -1);
        assert_se(CMP((int64_t) 0, INT64_MAX) == -1);
        assert_se(CMP(&str[2], &str[7]) == -1);
        assert_se(CMP(&str[2], &str[2]) == 0);
        assert_se(CMP(&str[7], (const char *)str) == 1);
        assert_se(CMP(str[2], str[7]) == 1);
        assert_se(CMP(str[7], *str) == 1);
        assert_se(CMP((const unsigned long long *)arr, &arr[3]) == -1);
        assert_se(CMP(*arr, arr[3]) == 1);
        assert_se(CMP(p, q) == -1);
        assert_se(CMP(q, p) == 1);
        assert_se(CMP(p, p) == 0);
        assert_se(CMP(q, q) == 0);
        assert_se(CLAMP(-5, 0, 1) == 0);
        assert_se(CLAMP(5, 0, 1) == 1);
        assert_se(CLAMP(5, -10, 1) == 1);
        assert_se(CLAMP(5, -10, 10) == 5);
        assert_se(CLAMP(CLAMP(0, -10, 10), CLAMP(-5, 10, 20), CLAMP(100, -5, 20)) == 10);
}

#pragma GCC diagnostic push
#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

static void test_container_of(void) {
        struct mytype {
                uint8_t pad1[3];
                uint64_t v1;
                uint8_t pad2[2];
                uint32_t v2;
        } myval = { };

        log_info("/* %s */", __func__);

        assert_cc(sizeof(myval) >= 17);
        assert_se(container_of(&myval.v1, struct mytype, v1) == &myval);
        assert_se(container_of(&myval.v2, struct mytype, v2) == &myval);
        assert_se(container_of(&container_of(&myval.v2,
                                             struct mytype,
                                             v2)->v1,
                               struct mytype,
                               v1) == &myval);
}

#pragma GCC diagnostic pop

static void test_div_round_up(void) {
        int div;

        log_info("/* %s */", __func__);

        /* basic tests */
        assert_se(DIV_ROUND_UP(0, 8) == 0);
        assert_se(DIV_ROUND_UP(1, 8) == 1);
        assert_se(DIV_ROUND_UP(8, 8) == 1);
        assert_se(DIV_ROUND_UP(12, 8) == 2);
        assert_se(DIV_ROUND_UP(16, 8) == 2);

        /* test multiple evaluation */
        div = 0;
        assert_se(DIV_ROUND_UP(div++, 8) == 0 && div == 1);
        assert_se(DIV_ROUND_UP(++div, 8) == 1 && div == 2);
        assert_se(DIV_ROUND_UP(8, div++) == 4 && div == 3);
        assert_se(DIV_ROUND_UP(8, ++div) == 2 && div == 4);

        /* overflow test with exact division */
        assert_se(sizeof(0U) == 4);
        assert_se(0xfffffffaU % 10U == 0U);
        assert_se(0xfffffffaU / 10U == 429496729U);
        assert_se(DIV_ROUND_UP(0xfffffffaU, 10U) == 429496729U);
        assert_se((0xfffffffaU + 10U - 1U) / 10U == 0U);
        assert_se(0xfffffffaU / 10U + !!(0xfffffffaU % 10U) == 429496729U);

        /* overflow test with rounded division */
        assert_se(0xfffffffdU % 10U == 3U);
        assert_se(0xfffffffdU / 10U == 429496729U);
        assert_se(DIV_ROUND_UP(0xfffffffdU, 10U) == 429496730U);
        assert_se((0xfffffffdU + 10U - 1U) / 10U == 0U);
        assert_se(0xfffffffdU / 10U + !!(0xfffffffdU % 10U) == 429496730U);
}

static void test_ptr_to_int(void) {
        log_info("/* %s */", __func__);

        /* Primary reason to have this test is to validate that pointers are large enough to hold entire int range */
        assert_se(PTR_TO_INT(INT_TO_PTR(0)) == 0);
        assert_se(PTR_TO_INT(INT_TO_PTR(1)) == 1);
        assert_se(PTR_TO_INT(INT_TO_PTR(-1)) == -1);
        assert_se(PTR_TO_INT(INT_TO_PTR(INT_MAX)) == INT_MAX);
        assert_se(PTR_TO_INT(INT_TO_PTR(INT_MIN)) == INT_MIN);
}

static void test_in_set(void) {
        log_info("/* %s */", __func__);

        assert_se(IN_SET(1, 1));
        assert_se(IN_SET(1, 1, 2, 3, 4));
        assert_se(IN_SET(2, 1, 2, 3, 4));
        assert_se(IN_SET(3, 1, 2, 3, 4));
        assert_se(IN_SET(4, 1, 2, 3, 4));
        assert_se(!IN_SET(0, 1));
        assert_se(!IN_SET(0, 1, 2, 3, 4));
}

static void test_foreach_pointer(void) {
        int a, b, c, *i;
        size_t k = 0;

        log_info("/* %s */", __func__);

        FOREACH_POINTER(i, &a, &b, &c) {
                switch (k) {

                case 0:
                        assert_se(i == &a);
                        break;

                case 1:
                        assert_se(i == &b);
                        break;

                case 2:
                        assert_se(i == &c);
                        break;

                default:
                        assert_not_reached();
                        break;
                }

                k++;
        }

        assert_se(k == 3);

        FOREACH_POINTER(i, &b) {
                assert_se(k == 3);
                assert_se(i == &b);
                k = 4;
        }

        assert_se(k == 4);

        FOREACH_POINTER(i, NULL, &c, NULL, &b, NULL, &a, NULL) {
                switch (k) {

                case 4:
                        assert_se(i == NULL);
                        break;

                case 5:
                        assert_se(i == &c);
                        break;

                case 6:
                        assert_se(i == NULL);
                        break;

                case 7:
                        assert_se(i == &b);
                        break;

                case 8:
                        assert_se(i == NULL);
                        break;

                case 9:
                        assert_se(i == &a);
                        break;

                case 10:
                        assert_se(i == NULL);
                        break;

                default:
                        assert_not_reached();
                        break;
                }

                k++;
        }

        assert_se(k == 11);
}

static void test_align_to(void) {
        log_info("/* %s */", __func__);

        assert_se(ALIGN_TO(0, 1) == 0);
        assert_se(ALIGN_TO(1, 1) == 1);
        assert_se(ALIGN_TO(2, 1) == 2);
        assert_se(ALIGN_TO(3, 1) == 3);
        assert_se(ALIGN_TO(4, 1) == 4);
        assert_se(ALIGN_TO(SIZE_MAX-1, 1) == SIZE_MAX-1);
        assert_se(ALIGN_TO(SIZE_MAX, 1) == SIZE_MAX);

        assert_se(ALIGN_TO(0, 2) == 0);
        assert_se(ALIGN_TO(1, 2) == 2);
        assert_se(ALIGN_TO(2, 2) == 2);
        assert_se(ALIGN_TO(3, 2) == 4);
        assert_se(ALIGN_TO(4, 2) == 4);
        assert_se(ALIGN_TO(SIZE_MAX-3, 2) == SIZE_MAX-3);
        assert_se(ALIGN_TO(SIZE_MAX-2, 2) == SIZE_MAX-1);
        assert_se(ALIGN_TO(SIZE_MAX-1, 2) == SIZE_MAX-1);
        assert_se(ALIGN_TO(SIZE_MAX, 2) == SIZE_MAX); /* overflow */

        assert_se(ALIGN_TO(0, 4) == 0);
        assert_se(ALIGN_TO(1, 4) == 4);
        assert_se(ALIGN_TO(2, 4) == 4);
        assert_se(ALIGN_TO(3, 4) == 4);
        assert_se(ALIGN_TO(4, 4) == 4);
        assert_se(ALIGN_TO(SIZE_MAX-3, 4) == SIZE_MAX-3);
        assert_se(ALIGN_TO(SIZE_MAX-2, 4) == SIZE_MAX); /* overflow */
        assert_se(ALIGN_TO(SIZE_MAX-1, 4) == SIZE_MAX); /* overflow */
        assert_se(ALIGN_TO(SIZE_MAX, 4) == SIZE_MAX);   /* overflow */

        assert_cc(CONST_ALIGN_TO(96, 512) == 512);
        assert_cc(CONST_ALIGN_TO(511, 512) == 512);
        assert_cc(CONST_ALIGN_TO(512, 512) == 512);
        assert_cc(CONST_ALIGN_TO(513, 512) == 1024);
        assert_cc(CONST_ALIGN_TO(sizeof(int), 64) == 64);

        assert_cc(__builtin_types_compatible_p(typeof(CONST_ALIGN_TO(4, 3)), void));
        assert_cc(__builtin_types_compatible_p(typeof(CONST_ALIGN_TO(SIZE_MAX, 512)), void));
}

static void test_flags(void) {
        enum {
                F1 = 1 << 0,
                F2 = 1 << 1,
                F3 = 1 << 2,
                F_ALL = F1 | F2 | F3
        };
        unsigned n, f;

        log_info("/* %s */", __func__);

        assert_se(FLAGS_SET(0, 0));
        assert_se(FLAGS_SET(F1, F1));
        assert_se(FLAGS_SET(F1 | F2, F1));
        assert_se(FLAGS_SET(F1 | F3, F1 | F3));
        assert_se(FLAGS_SET(F1 | F2 | F3, F_ALL));
        assert_se(!FLAGS_SET(0, F1));
        assert_se(!FLAGS_SET(F2, F1));
        assert_se(!FLAGS_SET(F1 | F2, F3));
        assert_se(!FLAGS_SET(F1 | F2, F1 | F3));
        assert_se(!FLAGS_SET(F1 | F2 | F3, ~F_ALL));

        // Check for no double eval.
        n = F2;
        f = F1;
        assert_se(!FLAGS_SET(--n, ++f));
        assert_se(n == F1);
        assert_se(f == F2);

        SET_FLAG(n, F3, true);
        assert_se(n == (F1 | F3));
        SET_FLAG(n, F2, false);
        assert_se(n == (F1 | F3));
        SET_FLAG(n, F3, false);
        assert_se(n == F1);
        SET_FLAG(n, F1, true);
        assert_se(n == F1);
        SET_FLAG(n, F1 | F3, true);
        assert_se(n == (F1 | F3));
        SET_FLAG(n, F_ALL, false);
        assert_se(n == 0);

        assert_se(UPDATE_FLAG(0, 0, true) == 0);
        assert_se(UPDATE_FLAG(0, F1, true) == F1);
        assert_se(UPDATE_FLAG(0, F1 | F2, true) == (F1 | F2));
        assert_se(UPDATE_FLAG(F1, 0, true) == F1);
        assert_se(UPDATE_FLAG(F1, F1, true) == F1);
        assert_se(UPDATE_FLAG(F1, F3, true) == (F1 | F3));
        assert_se(UPDATE_FLAG(F1, F1 | F3, true) == (F1 | F3));
        assert_se(UPDATE_FLAG(F1, F_ALL, true) == F_ALL);
        assert_se(UPDATE_FLAG(0, 0, false) == 0);
        assert_se(UPDATE_FLAG(0, F1, false) == 0);
        assert_se(UPDATE_FLAG(0, F1 | F2, false) == 0);
        assert_se(UPDATE_FLAG(F1, 0, false) == F1);
        assert_se(UPDATE_FLAG(F1, F1, false) == 0);
        assert_se(UPDATE_FLAG(F1, F3, false) == F1);
        assert_se(UPDATE_FLAG(F1, F1 | F3, false) == 0);
        assert_se(UPDATE_FLAG(F1, F2 | F3, false) == F1);
        assert_se(UPDATE_FLAG(F1, F_ALL, false) == 0);
        assert_se(UPDATE_FLAG(F_ALL, F_ALL, false) == 0);

        // Check for no double eval.
        n = F2;
        f = F1;
        assert_se(UPDATE_FLAG(--n, ++f, true) == (F1 | F2));
        assert_se(n == F1);
        assert_se(f == F2);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_align_power2();
        test_max();
        test_container_of();
        test_div_round_up();
        test_in_set();
        test_foreach_pointer();
        test_ptr_to_int();
        test_align_to();
        test_flags();

        return 0;
}
