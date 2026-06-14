/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>

#include "math-util.h"
#include "tests.h"

/* Computed at runtime via a noinline + volatile combination so the result crosses the function ABI
 * boundary at the FPU's current precision (80-bit on i386/x87). Used to probe fp_equal's handling
 * of excess precision — see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=323 for why
 * -fexcess-precision=standard doesn't fully cover the caller side of a function return on x87. */
static double _noinline_ one_tenth_via_division(void) {
        volatile double ten = 10.0;
        return 1.0 / ten;
}

TEST(iszero_safe) {
        /* zeros */
        assert_se(iszero_safe(0.0));
        assert_se(iszero_safe(-0.0));
        assert_se(iszero_safe(0e0));
        assert_se(iszero_safe(-0e0));
        assert_se(iszero_safe(0e+0));
        assert_se(iszero_safe(0e-0));
        assert_se(iszero_safe(-0e-0));
        assert_se(iszero_safe(-0e000));
        assert_se(iszero_safe(0e000));

        /* non-zero normal values */
        assert_se(!iszero_safe(42.0));
        assert_se(!iszero_safe(M_PI));
        assert_se(!iszero_safe(DBL_MAX));
        assert_se(!iszero_safe(-DBL_MAX));
        assert_se(!iszero_safe(DBL_MIN));
        assert_se(!iszero_safe(-DBL_MIN));
        assert_se(!iszero_safe(1 / DBL_MAX));

        /* subnormal values */
        assert_se(!iszero_safe(DBL_MIN / 2));
        assert_se(!iszero_safe(-DBL_MIN / 42));
        assert_se(!iszero_safe(1 / DBL_MAX / 2));

        /* too small values which cannot be in subnormal form */
        assert_se( iszero_safe(DBL_MIN / DBL_MAX));
        assert_se( iszero_safe(DBL_MIN / -DBL_MAX));
        assert_se( iszero_safe(-DBL_MIN / DBL_MAX));
        assert_se( iszero_safe(-DBL_MIN / -DBL_MAX));

        /* NaN or infinity */
        assert_se(!iszero_safe(NAN));
        assert_se(!iszero_safe(INFINITY));
        assert_se(!iszero_safe(-INFINITY));
        assert_se(!iszero_safe(1 / NAN));

        /* inverse of infinity */
        assert_se( iszero_safe(1 / INFINITY));
        assert_se( iszero_safe(1 / -INFINITY));
        assert_se( iszero_safe(-1 / INFINITY));
        assert_se( iszero_safe(-1 / -INFINITY));
        assert_se( iszero_safe(42 / -INFINITY));
        assert_se( iszero_safe(-42 / -INFINITY));
        assert_se( iszero_safe(DBL_MIN / INFINITY));
        assert_se( iszero_safe(DBL_MIN / -INFINITY));
        assert_se( iszero_safe(DBL_MAX / INFINITY / 2));
        assert_se( iszero_safe(DBL_MAX / -INFINITY * DBL_MAX));

        /* infinity / infinity is NaN */
        assert_se(!iszero_safe(INFINITY / INFINITY));
        assert_se(!iszero_safe(INFINITY * 2 / INFINITY));
        assert_se(!iszero_safe(INFINITY / DBL_MAX / INFINITY));
}

TEST(fp_equal) {
        /* normal values */
        assert_se( fp_equal(0.0, -0e0));
        assert_se( fp_equal(3.0, 3));
        assert_se(!fp_equal(3.000001, 3));
        assert_se( fp_equal(M_PI, M_PI));
        assert_se(!fp_equal(M_PI, -M_PI));
        assert_se( fp_equal(DBL_MAX, DBL_MAX));
        assert_se(!fp_equal(DBL_MAX, -DBL_MAX));
        assert_se(!fp_equal(-DBL_MAX, DBL_MAX));
        assert_se( fp_equal(-DBL_MAX, -DBL_MAX));
        assert_se( fp_equal(DBL_MIN, DBL_MIN));
        assert_se(!fp_equal(DBL_MIN, -DBL_MIN));
        assert_se(!fp_equal(-DBL_MIN, DBL_MIN));
        assert_se( fp_equal(-DBL_MIN, -DBL_MIN));

        /* subnormal values */
        assert_se( fp_equal(DBL_MIN / 10, DBL_MIN / 10));
        assert_se(!fp_equal(DBL_MIN / 10, -DBL_MIN / 10));
        assert_se(!fp_equal(-DBL_MIN / 10, DBL_MIN / 10));
        assert_se( fp_equal(-DBL_MIN / 10, -DBL_MIN / 10));
        assert_se(!fp_equal(DBL_MIN / 10, DBL_MIN / 15));
        assert_se(!fp_equal(DBL_MIN / 10, DBL_MIN / 15));

        /* subnormal difference */
        assert_se(!fp_equal(DBL_MIN / 10, DBL_MIN + DBL_MIN / 10));
        assert_se( fp_equal(3.0, 3.0 + DBL_MIN / 2)); /* 3.0 + DBL_MIN / 2 is truncated to 3.0 */

        /* too small values */
        assert_se( fp_equal(DBL_MIN / DBL_MAX, -DBL_MIN / DBL_MAX));

        /* NaN or infinity */
        assert_se(!fp_equal(NAN, NAN));
        assert_se(!fp_equal(NAN, 0));
        assert_se(!fp_equal(NAN, INFINITY));
        assert_se(!fp_equal(INFINITY, INFINITY));
        assert_se(!fp_equal(INFINITY, -INFINITY));
        assert_se(!fp_equal(-INFINITY, INFINITY));
        assert_se(!fp_equal(-INFINITY, -INFINITY));

        /* inverse of infinity */
        assert_se( fp_equal(0, 1 / INFINITY));
        assert_se( fp_equal(42 / INFINITY, 1 / -INFINITY));
        assert_se(!fp_equal(42 / INFINITY, INFINITY / INFINITY));

        assert_se( fp_equal(one_tenth_via_division(), 0.1));
}

TEST(xexp10i) {
        /* Table-lookup range: every value is exact in binary64 */
        ASSERT_TRUE(fp_equal(xexp10i(0), 1.0));
        ASSERT_TRUE(fp_equal(xexp10i(1), 10.0));
        ASSERT_TRUE(fp_equal(xexp10i(2), 100.0));
        ASSERT_TRUE(fp_equal(xexp10i(22), 1e22));

        /* Negative exponents */
        ASSERT_TRUE(fp_equal(xexp10i(-1), 0.1));
        ASSERT_TRUE(fp_equal(xexp10i(-3), 0.001));

        /* Beyond the table: result still matches a plain 10.0 multiplication chain (no precision
         * claim beyond binary64) */
        ASSERT_TRUE(xexp10i(23) > 0.9e23 && xexp10i(23) < 1.1e23);
        ASSERT_TRUE(xexp10i(100) > 0.9e100 && xexp10i(100) < 1.1e100);

        /* Overflow saturates to +Inf, underflow to 0 — matching glibc exp10() */
        ASSERT_TRUE(isinf(xexp10i(400)));
        ASSERT_TRUE(fp_equal(xexp10i(-400), 0.0));

        /* Pathological inputs must still terminate quickly thanks to the internal cap */
        ASSERT_TRUE(isinf(xexp10i(INT_MAX)));
        ASSERT_TRUE(fp_equal(xexp10i(INT_MIN), 0.0));

        /* Regression guard for the DBL_MAX round-trip described in math-util.c: 10^308 must be small
         * enough that DBL_MAX's mantissa (≈ 1.7976931348623157) multiplied by it does not overflow
         * to +Inf. Delegating to __builtin_powi(10.0, n) here breaks this — libgcc's __powidf2
         * accumulates a few ULPs of error through repeated squaring, and the product spills over.
         * Matching test-json's delta of 0.0001, the reconstructed value must land within 0.01% of
         * DBL_MAX. */
        double dbl_max_reconstructed = 1.7976931348623157 * xexp10i(308);
        ASSERT_FALSE(isinf(dbl_max_reconstructed));
        ASSERT_TRUE(ABS(1.0 - DBL_MAX / dbl_max_reconstructed) < 0.0001);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
