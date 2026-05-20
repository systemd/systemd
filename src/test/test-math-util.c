/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>

#include "math-util.h"
#include "tests.h"

/* Arbitrary nonzero finite double used as a "well-behaved value" probe across the tests below. */
#define TEST_DOUBLE 1.234567890123456

TEST(xiszero) {
        /* zeros */
        ASSERT_TRUE(iszero_safe(0.0));
        ASSERT_TRUE(iszero_safe(-0.0));
        ASSERT_TRUE(iszero_safe(0e0));
        ASSERT_TRUE(iszero_safe(-0e0));
        ASSERT_TRUE(iszero_safe(0e+0));
        ASSERT_TRUE(iszero_safe(0e-0));
        ASSERT_TRUE(iszero_safe(-0e-0));
        ASSERT_TRUE(iszero_safe(-0e000));
        ASSERT_TRUE(iszero_safe(0e000));

        /* non-zero normal values */
        ASSERT_FALSE(iszero_safe(42.0));
        ASSERT_FALSE(iszero_safe(TEST_DOUBLE));
        ASSERT_FALSE(iszero_safe(DBL_MAX));
        ASSERT_FALSE(iszero_safe(-DBL_MAX));
        ASSERT_FALSE(iszero_safe(DBL_MIN));
        ASSERT_FALSE(iszero_safe(-DBL_MIN));
        ASSERT_FALSE(iszero_safe(1 / DBL_MAX));

        /* subnormal values */
        ASSERT_FALSE(iszero_safe(DBL_MIN / 2));
        ASSERT_FALSE(iszero_safe(-DBL_MIN / 42));
        ASSERT_FALSE(iszero_safe(1 / DBL_MAX / 2));

        /* too small values which cannot be in subnormal form */
        ASSERT_TRUE(iszero_safe(DBL_MIN / DBL_MAX));
        ASSERT_TRUE(iszero_safe(DBL_MIN / -DBL_MAX));
        ASSERT_TRUE(iszero_safe(-DBL_MIN / DBL_MAX));
        ASSERT_TRUE(iszero_safe(-DBL_MIN / -DBL_MAX));

        /* NaN or infinity */
        ASSERT_FALSE(iszero_safe(NAN));
        ASSERT_FALSE(iszero_safe(INFINITY));
        ASSERT_FALSE(iszero_safe(-INFINITY));
        ASSERT_FALSE(iszero_safe(1 / NAN));

        /* inverse of infinity */
        ASSERT_TRUE(iszero_safe(1 / INFINITY));
        ASSERT_TRUE(iszero_safe(1 / -INFINITY));
        ASSERT_TRUE(iszero_safe(-1 / INFINITY));
        ASSERT_TRUE(iszero_safe(-1 / -INFINITY));
        ASSERT_TRUE(iszero_safe(42 / -INFINITY));
        ASSERT_TRUE(iszero_safe(-42 / -INFINITY));
        ASSERT_TRUE(iszero_safe(DBL_MIN / INFINITY));
        ASSERT_TRUE(iszero_safe(DBL_MIN / -INFINITY));
        ASSERT_TRUE(iszero_safe(DBL_MAX / INFINITY / 2));
        ASSERT_TRUE(iszero_safe(DBL_MAX / -INFINITY * DBL_MAX));

        /* infinity / infinity is NaN */
        ASSERT_FALSE(iszero_safe(INFINITY / INFINITY));
        ASSERT_FALSE(iszero_safe(INFINITY * 2 / INFINITY));
        ASSERT_FALSE(iszero_safe(INFINITY / DBL_MAX / INFINITY));
}

TEST(fp_equal) {
        /* normal values */
        ASSERT_TRUE(fp_equal(0.0, -0e0));
        ASSERT_TRUE(fp_equal(3.0, 3));
        ASSERT_FALSE(fp_equal(3.000001, 3));
        ASSERT_TRUE(fp_equal(TEST_DOUBLE, TEST_DOUBLE));
        ASSERT_FALSE(fp_equal(TEST_DOUBLE, -TEST_DOUBLE));
        ASSERT_TRUE(fp_equal(DBL_MAX, DBL_MAX));
        ASSERT_FALSE(fp_equal(DBL_MAX, -DBL_MAX));
        ASSERT_FALSE(fp_equal(-DBL_MAX, DBL_MAX));
        ASSERT_TRUE(fp_equal(-DBL_MAX, -DBL_MAX));
        ASSERT_TRUE(fp_equal(DBL_MIN, DBL_MIN));
        ASSERT_FALSE(fp_equal(DBL_MIN, -DBL_MIN));
        ASSERT_FALSE(fp_equal(-DBL_MIN, DBL_MIN));
        ASSERT_TRUE(fp_equal(-DBL_MIN, -DBL_MIN));

        /* subnormal values */
        ASSERT_TRUE(fp_equal(DBL_MIN / 10, DBL_MIN / 10));
        ASSERT_FALSE(fp_equal(DBL_MIN / 10, -DBL_MIN / 10));
        ASSERT_FALSE(fp_equal(-DBL_MIN / 10, DBL_MIN / 10));
        ASSERT_TRUE(fp_equal(-DBL_MIN / 10, -DBL_MIN / 10));
        ASSERT_FALSE(fp_equal(DBL_MIN / 10, DBL_MIN / 15));
        ASSERT_FALSE(fp_equal(DBL_MIN / 10, DBL_MIN / 15));

        /* subnormal difference */
        ASSERT_FALSE(fp_equal(DBL_MIN / 10, DBL_MIN + DBL_MIN / 10));
        ASSERT_TRUE(fp_equal(3.0, 3.0 + DBL_MIN / 2)); /* 3.0 + DBL_MIN / 2 is truncated to 3.0 */

        /* too small values */
        ASSERT_TRUE(fp_equal(DBL_MIN / DBL_MAX, -DBL_MIN / DBL_MAX));

        /* NaN or infinity */
        ASSERT_FALSE(fp_equal(NAN, NAN));
        ASSERT_FALSE(fp_equal(NAN, 0));
        ASSERT_FALSE(fp_equal(NAN, INFINITY));
        ASSERT_FALSE(fp_equal(INFINITY, INFINITY));
        ASSERT_FALSE(fp_equal(INFINITY, -INFINITY));
        ASSERT_FALSE(fp_equal(-INFINITY, INFINITY));
        ASSERT_FALSE(fp_equal(-INFINITY, -INFINITY));

        ASSERT_TRUE(fp_equal(0, 1 / INFINITY));
        ASSERT_TRUE(fp_equal(42 / INFINITY, 1 / -INFINITY));
        ASSERT_FALSE(fp_equal(42 / INFINITY, INFINITY / INFINITY));
}

TEST(xisnan) {
        /* NaN flavours */
        ASSERT_TRUE(xisnan(NAN));
        ASSERT_TRUE(xisnan(-NAN));
        ASSERT_TRUE(xisnan(0.0 / 0.0));
        ASSERT_TRUE(xisnan(INFINITY - INFINITY));
        ASSERT_TRUE(xisnan(INFINITY / INFINITY));
        ASSERT_TRUE(xisnan(0.0 * INFINITY));
        ASSERT_TRUE(xisnan(1 / NAN));

        /* Non-NaN values */
        ASSERT_FALSE(xisnan(0.0));
        ASSERT_FALSE(xisnan(-0.0));
        ASSERT_FALSE(xisnan(42.0));
        ASSERT_FALSE(xisnan(-42.0));
        ASSERT_FALSE(xisnan(TEST_DOUBLE));
        ASSERT_FALSE(xisnan(DBL_MIN));
        ASSERT_FALSE(xisnan(DBL_MAX));
        ASSERT_FALSE(xisnan(DBL_MIN / 2));         /* subnormal */
        ASSERT_FALSE(xisnan(INFINITY));
        ASSERT_FALSE(xisnan(-INFINITY));
}

TEST(xisinf) {
        /* +Inf, -Inf, and arithmetic that produces them */
        ASSERT_TRUE(xisinf(INFINITY));
        ASSERT_TRUE(xisinf(-INFINITY));
        ASSERT_TRUE(xisinf(DBL_MAX * 2));
        ASSERT_TRUE(xisinf(-DBL_MAX * 2));
        ASSERT_TRUE(xisinf(1.0 / 0.0));
        ASSERT_TRUE(xisinf(-1.0 / 0.0));

        /* Non-infinity values */
        ASSERT_FALSE(xisinf(0.0));
        ASSERT_FALSE(xisinf(-0.0));
        ASSERT_FALSE(xisinf(42.0));
        ASSERT_FALSE(xisinf(-42.0));
        ASSERT_FALSE(xisinf(TEST_DOUBLE));
        ASSERT_FALSE(xisinf(DBL_MIN));
        ASSERT_FALSE(xisinf(DBL_MAX));              /* finite, just close to the edge */
        ASSERT_FALSE(xisinf(DBL_MIN / 2));          /* subnormal */
        ASSERT_FALSE(xisinf(NAN));
        ASSERT_FALSE(xisinf(-NAN));
}

TEST(xexp2i) {
        /* Bit-shift fast path: |n| < 64 must be exact */
        ASSERT_TRUE(fp_equal(xexp2i(0), 1.0));
        ASSERT_TRUE(fp_equal(xexp2i(1), 2.0));
        ASSERT_TRUE(fp_equal(xexp2i(10), 1024.0));
        ASSERT_TRUE(fp_equal(xexp2i(52), (double) (UINT64_C(1) << 52)));
        ASSERT_TRUE(fp_equal(xexp2i(63), (double) (UINT64_C(1) << 63)));

        /* Negative exponents in the fast path are exact too */
        ASSERT_TRUE(fp_equal(xexp2i(-1), 0.5));
        ASSERT_TRUE(fp_equal(xexp2i(-2), 0.25));
        ASSERT_TRUE(fp_equal(xexp2i(-10), 1.0 / 1024.0));

        /* Beyond the fast path but still representable */
        ASSERT_TRUE(fp_equal(xexp2i(64), 2.0 * (double) (UINT64_C(1) << 63)));
        ASSERT_FALSE(xisinf(xexp2i(1023)));          /* DBL_MAX is just below 2^1024 */
        ASSERT_TRUE(xexp2i(1023) > 8e307 && xexp2i(1023) < 9e307);

        /* Overflow / underflow saturation */
        ASSERT_TRUE(xisinf(xexp2i(1024)));
        ASSERT_TRUE(xisinf(xexp2i(2000)));
        ASSERT_TRUE(fp_equal(xexp2i(-1075), 0.0));
        ASSERT_TRUE(fp_equal(xexp2i(-2000), 0.0));

        /* Pathological extremes must still terminate */
        ASSERT_TRUE(xisinf(xexp2i(INT_MAX)));
        ASSERT_TRUE(fp_equal(xexp2i(INT_MIN), 0.0));
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
        ASSERT_TRUE(xisinf(xexp10i(400)));
        ASSERT_TRUE(fp_equal(xexp10i(-400), 0.0));

        /* Pathological inputs must still terminate quickly thanks to the internal cap */
        ASSERT_TRUE(xisinf(xexp10i(INT_MAX)));
        ASSERT_TRUE(fp_equal(xexp10i(INT_MIN), 0.0));

        /* Regression guard for the DBL_MAX round-trip described in math-util.c: 10^308 must be small
         * enough that DBL_MAX's mantissa (≈ 1.7976931348623157) multiplied by it does not overflow
         * to +Inf. Delegating to __builtin_powi(10.0, n) here breaks this — libgcc's __powidf2
         * accumulates a few ULPs of error through repeated squaring, and the product spills over.
         * Matching test-json's delta of 0.0001, the reconstructed value must land within 0.01% of
         * DBL_MAX. */
        double dbl_max_reconstructed = 1.7976931348623157 * xexp10i(308);
        ASSERT_FALSE(xisinf(dbl_max_reconstructed));
        ASSERT_TRUE(ABS(1.0 - DBL_MAX / dbl_max_reconstructed) < 0.0001);
}

/* True iff |x - y| / |y| < tol. y must be non-zero. */
static bool approx_equal(double x, double y, double tol) {
        double d = x - y;
        if (d < 0)
                d = -d;
        double ay = y < 0 ? -y : y;
        return d < tol * ay;
}

TEST(double_nth_root) {
        /* n == 1 is the identity */
        ASSERT_TRUE(fp_equal(double_nth_root(1.0, 1), 1.0));
        ASSERT_TRUE(fp_equal(double_nth_root(42.0, 1), 42.0));
        ASSERT_TRUE(fp_equal(double_nth_root(1e100, 1), 1e100));
        ASSERT_TRUE(fp_equal(double_nth_root(1e-100, 1), 1e-100));

        /* a == 1 is a fixed point for every n */
        ASSERT_TRUE(fp_equal(double_nth_root(1.0, 2), 1.0));
        ASSERT_TRUE(fp_equal(double_nth_root(1.0, 5), 1.0));
        ASSERT_TRUE(fp_equal(double_nth_root(1.0, 100), 1.0));

        /* Square roots of perfect squares */
        ASSERT_TRUE(approx_equal(double_nth_root(4.0, 2), 2.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(9.0, 2), 3.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(16.0, 2), 4.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(10000.0, 2), 100.0, 1e-12));

        /* Square roots of non-squares */
        ASSERT_TRUE(approx_equal(double_nth_root(2.0, 2), 1.4142135623730951, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(0.25, 2), 0.5, 1e-12));

        /* Cube roots */
        ASSERT_TRUE(approx_equal(double_nth_root(8.0, 3), 2.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(27.0, 3), 3.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(1000.0, 3), 10.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(0.125, 3), 0.5, 1e-12));

        /* Higher roots */
        ASSERT_TRUE(approx_equal(double_nth_root(16.0, 4), 2.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(32.0, 5), 2.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root(1024.0, 10), 2.0, 1e-12));
        ASSERT_TRUE(approx_equal(double_nth_root((double) (UINT64_C(1) << 30), 30), 2.0, 1e-12));

        /* Magnitude extremes — the exponent-aware seed is what makes these converge in a handful
         * of iterations regardless of how large a is */
        ASSERT_TRUE(approx_equal(double_nth_root(1e100, 2), 1e50, 1e-10));
        ASSERT_TRUE(approx_equal(double_nth_root(1e-100, 2), 1e-50, 1e-10));
        ASSERT_TRUE(approx_equal(double_nth_root(1e30, 10), 1e3, 1e-10));
        ASSERT_TRUE(approx_equal(double_nth_root(1e-30, 10), 1e-3, 1e-10));
        ASSERT_TRUE(approx_equal(double_nth_root(DBL_MAX, 2), xsqrt(DBL_MAX), 1e-10));
        ASSERT_TRUE(approx_equal(double_nth_root(DBL_MIN, 2), xsqrt(DBL_MIN), 1e-10));

        /* Round-trip: (a^(1/n))^n ≈ a for a representative spread */
        double a;
        for (unsigned n = 2; n <= 12; n++)
                FOREACH_ARGUMENT(a, 0.001, 0.5, 2.0, 7.0, 100.0, 12345.6789, 1e15) {
                        double y = double_nth_root(a, n);
                        double back = 1.0;
                        for (unsigned i = 0; i < n; i++)
                                back *= y;
                        ASSERT_TRUE(approx_equal(back, a, 1e-10));
                }

        /* Matches the actual usage in service_restart_usec_next(): ratio between a min and max
         * restart delay, split into a handful of steps */
        double step = double_nth_root(60.0 / 0.1, 5);  /* 100ms → 60s in 5 steps */
        double acc = 0.1;
        for (unsigned i = 0; i < 5; i++)
                acc *= step;
        ASSERT_TRUE(approx_equal(acc, 60.0, 1e-10));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
